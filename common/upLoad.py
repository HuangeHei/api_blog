import os
from random import Random

class Upload():
    '''
    1:FILE :req.FILE['file']
    2:PATH : root_path
    3:randomlength = 28
    '''
    def __init__(self,file,PATH,randomlength=28):
        self.file = file
        self.PTAH = PATH
        self.name = ''
        self.randomlength = randomlength    # 生成随机字符串 28位

    def random_str(self):
        str = ''
        chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
        length = len(chars) - 1
        random = Random()
        for i in range(self.randomlength):
            str += chars[random.randint(0,length)]
        return str

    def upfile_save(self):  # 存储上传文件

        fileBuff = self.file.__str__()
        fileBuff = fileBuff.split('.')
        fileBuff[0] = self.random_str()
        self.filename = '%s.%s' % (fileBuff[0], fileBuff[1])
        self.PTAH = os.path.join(self.PTAH, self.filename)
        print(self.PTAH)
        with open(self.PTAH, 'wb+') as temp_fp:
            temp_fp.write(self.file.read())

        return self.filename