#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import sys
import time
import random
import pickle
from loguru import logger
import requests
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from base64 import b64decode, b64encode
from prettytable import PrettyTable

from config import Config
import captcha as cpt
from utils import score_to_gpa

CollegeCode = {
    '0701': '数学',
    '0702': '物理',
    '0704': '天文',
    '0703': '化学',
    '0802': '材料',
    '0710': '生命',
    '0706': '地球',
    '0705': '资环',
    '0812': '计算',
    '0808': '电子',
    '0801': '工程',
    '1256': '工程',
    '1205': '经管',
    '0201': '经管',
    '0202': '公管',
    '0301': '公管',
    '1204': '公管',
    '0503': '人文',
    '0502': '外语',
    '16': '中丹',
    '17': '国际',
    '1001': '存济',
    '0854': '微电',
    '0839': '网络',
    '2001': '未来',
    '22': '',
    '0101': '马克',
    '0305': '马克',
    '0402': '心理',
    '0811': '人工',
    '0702': '纳米',
    '1302': '艺术',
    '0452': '体育',
}


class Login:
    page = 'https://sep.ucas.ac.cn'
    url = page + '/slogin'
    system = page + '/portal/site/226/821'
    pic = page + '/changePic'


class Course:
    base = 'https://jwxk.ucas.ac.cn'
    identify = base + '/login?Identity='
    selected = base + '/courseManage/selectedCourse'
    selection = base + '/courseManage/main'
    category = base + '/courseManage/selectCourse?s='
    save = base + '/courseManage/saveCourse?s='
    score = base + '/score/yjs/all.json'
    captcha = base + '/captchaImage'


class BadNetwork(Exception):
    pass


class AuthInvalid(Exception):
    pass


class Cli(object):
    headers = {
        'Connection': 'keep-alive',
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:61.0) Gecko/20100101 Firefox/61.0',
        'Accept-Encoding': 'gzip, deflate, sdch',
        'Accept-Language': 'zh-CN,zh;q=0.8,en;q=0.6',
    }

    def __init__(self, user, password):
        super(Cli, self).__init__()
        self.gpa = None
        self.student = None
        self.courseFinished = None
        self.logger = logger
        self.s = requests.Session()
        self.s.headers = self.headers
        self.s.timeout = Config.timeout
        self.login(user, password)
        self.initCourse()

    def get(self, url, *args, **kwargs):
        r = self.s.get(url, *args, **kwargs)
        if r.status_code != requests.codes.ok:
            raise BadNetwork
        return r

    def post(self, url, *args, **kwargs):
        r = self.s.post(url, *args, **kwargs)
        if r.status_code != requests.codes.ok:
            raise BadNetwork
        return r

    def encode_password(self, password):
        r = self.get(url=Login.page)
        pubkey_re = re.compile(r"jsePubKey = '(.*)';")
        pubkey = pubkey_re.findall(r.text)[0]
        pubkey = '-----BEGIN PUBLIC KEY-----\n' + pubkey + '\n-----END PUBLIC KEY-----'
        cipher = Cipher_PKCS1_v1_5.new(RSA.importKey(pubkey))
        cipher_b64 = cipher.encrypt(password.encode())
        return b64encode(cipher_b64).decode()

    def initCourse(self):
        self.courseid = []
        with open('courseid', 'r', encoding='utf8') as fh:
            for c in fh:
                tmp = c.replace(' ', '').strip()
                if len(tmp):
                    self.courseid.append(tmp.split(','))

    def login(self, user, password):
        if os.path.exists('cookie.dat'):
            self.load()
            if self.auth():
                return
            else:
                self.logger.debug('cookie expired...')
                os.unlink('cookie.dat')
        self.get(Login.page)
        password_rsa = self.encode_password(password)
        data = {
            'userName': user,
            'pwd': password_rsa,
            'sb': 'sb'
        }
        login_captcha = self.get(Login.pic).content
        cert_code = cpt.recognize_login(login_captcha)
        self.logger.debug(f'login cert code = {cert_code}')
        data['certCode'] = cert_code
        self.post(Login.url, data=data)
        if 'sepuser' not in self.s.cookies.get_dict():
            self.logger.error('login fail...')
            sys.exit()
        self.save()
        self.logger.debug(f'cookies saved = {self.s.cookies.get_dict()}')
        self.auth()

    def auth(self):
        r = self.get(Login.system)
        identity = r.text.split('<meta http-equiv="refresh" content="0;url=')
        if len(identity) < 2:
            self.logger.error('login fail')
            return False
        identity_url = identity[1].split('"')[0]
        # self.identity = identity_url.split('Identity=')[1].split('&')[0]
        self.get(identity_url)
        return True

    def save(self):
        self.logger.debug('save cookie as cookie.dat')
        with open('cookie.dat', 'wb') as f:
            pickle.dump(self.s.cookies, f)

    def load(self):
        self.logger.debug('loading cookie...')
        with open('cookie.dat', 'rb') as f:
            cookies = pickle.load(f)
            self.s.cookies = cookies

    def enroll(self):
        r = self.get(Course.selection)
        if 'loginSuccess' not in r.text:
            # <label id="loginSuccess" class="success"></label>
            raise AuthInvalid
        course_id = []
        self.logger.debug(self.courseid)
        for info in self.courseid:
            cid = info[0]
            college = info[1] if len(info) > 1 else None
            if cid in r.text:
                self.logger.info('course %s already selected' % cid)
                continue
            error = self.enrollCourse(cid, college)
            if error and error != "Time Unavailable":
                self.logger.debug(
                    'try enroll course %s fail: %s' % (cid, error))
                course_id.append(info)
            else:
                self.logger.debug("enroll course %s success" % cid)
        return course_id

    def enrollCourse(self, cid, college):
        r = self.get(Course.selection)
        depRe = re.compile(r'<label for="id_([0-9]{3})">(.*)<\/label>')
        deptIds = depRe.findall(r.text)
        collegeName = college if college else CollegeCode[cid[:4]]
        for dep in deptIds:
            if collegeName in dep[1]:
                deptid = dep[0]
                break
        identity = r.text.split('action="/courseManage/selectCourse?s=')[1].split('"')[0]
        data = {
            "deptIds": deptid,
            "sb": 0
        }
        categoryUrl = Course.category + identity
        r = self.post(categoryUrl, data=data)
        courseCodeRe = re.compile(r'<span id="courseCode_([A-F0-9]{16})">' + cid + "<\/span>")
        courseCode = courseCodeRe.findall(r.text)
        isUnvalidSelectCourse = "未开通选课权限" in r.text
        if isUnvalidSelectCourse:
            return "Unvalid Select Course"
        if not courseCode:
            return "Course Not Found"

        unselectableRe = re.compile(r'type="checkbox" name="sids" value="' + courseCode[0] + r'"  disabled/>')
        unselectable = len(unselectableRe.findall(r.text)) > 0
        if unselectable:
            return "Unselectable Course"

        fidRe = re.compile(r'"fid_' + courseCode[0] + r'" value="([0-9]{6})"')
        fid_temp = fidRe.findall(r.text)
        code = courseCode[0]
        fid = fid_temp[0]
        csrf_re = re.compile(r'name="_csrftoken" value="(.*)"')
        csrf_token = csrf_re.findall(r.text)[0]
        vcode = None

        repeatFlag = 0
        while repeatFlag < Config.captchaRepeatTime:
            while vcode is None:
                enroll_captcha = self.get(Course.captcha).content
                vcode = cpt.recognize(enroll_captcha)
            data = {
                "_csrftoken": csrf_token,
                "deptIds": deptid,
                "sids": code,
                "vcode": vcode,
                f"fid_{code}": fid,
            }
            courseSaveUrl = Course.save + identity

            self.s.headers["Referer"] = categoryUrl
            r = self.post(courseSaveUrl, data=data)
            del self.s.headers["Referer"]
            if '验证码不正确' in r.text:
                repeatFlag += 1
            elif '选课成功' in r.text:
                return None
            elif '超过限选人数' in r.text:
                return "CourStack Overflow"
            elif '上课时间冲突' in r.text:
                return "Time Unavailable"
            else:
                return "Failure in Enrollment"
        return f'Captcha Fails {repeatFlag} Times'

    def getStudentInfo(self):
        r = self.get(Course.score)
        if 'gpa' not in r.text:
            # <label id="loginSuccess" class="success"></label>
            raise AuthInvalid
        jsonobj = json.loads(r.text)
        self.student = jsonobj['student']
        self.gpa = jsonobj['gpa']
        self.courseFinished = jsonobj['list']

    def score(self):
        self.getStudentInfo()
        self.logger.info('making transcript...')
        table = PrettyTable()
        table.title = f"{self.student['xm']} - {self.student['xh']} 的成绩单  GPA = {self.gpa}"
        table.field_names = ['序号', '课程名称', '学分', '得分', '绩点']
        for i, v in enumerate(self.courseFinished):
            table.add_row([i + 1, v['courseName'], v['courseCredit'], v['score'], score_to_gpa(v['score'])])
        print(table)


def main():
    with open('auth', 'r', encoding='utf8') as fh:
        user = fh.readline().strip()
        password = fh.readline().strip()
    c = Cli(user, password)
    func = None
    if 'enroll' in sys.argv:
        func = 'enroll'
    elif 'gpa' in sys.argv:
        func = 'transcript'
    elif 'clean_cookie' in sys.argv:
        os.unlink('cookie.dat')
        sys.exit()
    reauth = False
    while True:
        try:
            if reauth:
                c.auth()
                reauth = False
            if func == 'enroll':
                courseid = c.enroll()
                if not courseid:
                    break
                c.courseid = courseid
                time.sleep(Config.minIdle - random.random() * (Config.minIdle - Config.maxIdle))
            elif func == 'transcript':
                c.score()
                break
        except IndexError as e:
            c.logger.info("Course Not Found")
            time.sleep(Config.minIdle - random.random() * (Config.minIdle - Config.maxIdle))
        except KeyboardInterrupt as e:
            c.logger.info('user aborted')
            break
        except (
                BadNetwork,
                requests.exceptions.ConnectionError,
                requests.exceptions.ConnectTimeout,
        ) as e:
            c.logger.debug('network error')
        except AuthInvalid as e:
            c.logger.error('wait for user operating')
            reauth = True
            time.sleep(Config.waitForUser)
            # reauth next loop
        except Exception as e:
            c.logger.error(repr(e))


if __name__ == '__main__':
    main()
