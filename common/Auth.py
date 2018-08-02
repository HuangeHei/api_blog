#from blog.models import User
from django.shortcuts import render,HttpResponse
from django.contrib.auth.hashers import make_password, check_password
import json
import logging


auth_log = logging.getLogger('auth')  # auth 需要自己单独的log

if not auth_log:
    '''
        此方法为默认的偷懒办法
    '''
    class default_log:
    
        @classmethod
        def error(cls,text):
            print(text)
        
        @classmethod
        def info(cls,text):
            print(text)

    auth_log = default_log   
            
    








'''
    auth 需要在setting中设置一个User_Model 以备使用
    User_Model 最起码具备

    1 user_name
    2 user_passwd

'''



class Auth():
    
    def __init__(self):
        pass

    @classmethod
    def create_user(cls,user_model,user_info):
        '''
        :param user_model: model
        :param user_info:{
                 user_name:'user_name',
                 user_passwd:'user_passwd',
               }
        :return:{
            'status':false,
            'error':'重复的用户'
        }
        '''

        check_rep = user_model.objects.filter(user_name = user_info['user_name']) #检查重复

        if len(check_rep) == 0 :

            passwd = make_password(user_info['user_passwd'],None,'pbkdf2_sha256')

            try:

                ret = user_model.objects.create(user_name = user_info['user_name'],user_passwd = passwd)  # 检查重复
                return {
                    'status':True,
                    'model':ret
                }

            except Exception as E:

                auth_log.error('发生错误%s' % E)

                return {
                    'status': False,
                    'error': E
                }

        else:
            return {
                'status':False,
                'error':'重复的用户'
            }

    @classmethod
    def re_passwd(cls,user,old_passwd,new_passwd):
        '''
        :param user: user_model
        :param passwd:
        :return:false
        '''

        if len(new_passwd) != 0:


            if check_password(old_passwd,user.user_passwd):

                try:

                    passwd = make_password(new_passwd, None, 'pbkdf2_sha256')
                    user.user_passwd = passwd
                    user.save()

                    return {
                        'status': True,
                    }

                except Exception as E:

                    auth_log.error('发生错误%s' % E)

                    return {
                        'status': False,
                        'error': E
                    }

            else:

                return {
                    'status': False,
                    'error': '原始密码错误'
                }



        else:
            return {
                'status': False,
                'error': '新密码为空'
            }



    @classmethod
    def login_status(cls,req):

        if  req.session.get('user_id',False) and (req.session.get('status',False) == True):
            return {
                'status':True,
                'user_name':req.session['user_name'],
                'user_id': req.session['user_id']
            }
        else:
            req.session.delete()
            return {
                'status':False
            }

    @classmethod
    def is_login(cls,user_name,passwd,req):

        if user_name and passwd:

            try:
                print('user_name ',user_name )
                user_obj = User.objects.get(user_name = user_name)

            except Exception as E:

                return {
                    'status':False,
                    'error':'无此用户'
                }


            ret = check_password(passwd, user_obj.user_passwd)

            if ret:
                if cls.login_status(req)['status']:# 检查后台session是否设置了

                    return {
                        'status':True
                    }
                else:

                    req.session['user_id'] = user_obj.id           # user_id
                    req.session['user_name'] = user_obj.user_name  # user_name
                    req.session['status'] = True

                    return {
                        'status': True
                    }
            else:
                return {
                    'status': False,
                    'error': '账号或密码错误'
                }
        else:

            return {
                'status':False,
                'error':'账号或密码为空!'
            }

    @classmethod
    def out_login(cls,req):
        ret_buf = cls.login_status(req)

        if ret_buf['status']:

            req.session.delete()

            #if not cls.login_status(req)['status']:

            return {
                'status':True,
            }

        else:
            return {
                'status':False,
                'error':'并没有登录!'
            }

    @classmethod
    def auth(cls):

        def outer_wrapper(func):

            def wap(*args, **kwargs):

                request = args[0]  # request

                if Auth.login_status(request)['status']:
                    '''不再进行后台数据验证
                    try:

                        obj = User.objects.get(id = request.session['user_id'])

                    except Exception as e:

                        log_server.error('用户不存在 进入用户%s' % request.session['user_name'])

                        return HttpResponse(json.dumps({
                            'status':False,
                            'error':'用户不存在'
                        }))
                    '''

                    return func(*args, **kwargs)  # 执行函数

                else:

                    return HttpResponse(json.dumps({
                        'status':False,
                        'error':'用户没有登录'
                    }))

            return wap

        return outer_wrapper






