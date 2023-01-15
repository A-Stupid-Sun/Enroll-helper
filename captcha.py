import ddddocr
import time
import PIL.Image

int_char = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
ocr = ddddocr.DdddOcr(show_ad=False)


def recognize(captcha_bytes):
    with open('cache.jpg', 'wb') as f:
        f.write(captcha_bytes)
    image = PIL.Image.open('cache.jpg')
    image = image.rotate(-20)
    image.save('cache.jpg')
    with open('cache.jpg', 'rb') as f:
        captcha_bytes = f.read()
    res = ocr.classification(captcha_bytes)
    if len(res) < 3:
        return None
    if not (res[0] in int_char and res[2] in int_char):
        return None
    print(f"res = {res}")
    r1 = int(res[0])
    r2 = int(res[2])
    op = res[1]
    if op == '+':
        return r1 + r2
    elif op == '*' or op == 'x' or op == 'X':
        return r1 * r2
    elif op == '/':
        return r1 // r2
    else:
        return None


def recognize_login(captcha_bytes):
    return ocr.classification(captcha_bytes)


if __name__ == '__main__':
    with open('captchaImage2.jpg', 'rb') as f:
        image_bytes = f.read()
    res = recognize(image_bytes)
    print(res)
