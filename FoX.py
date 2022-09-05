Black="\033[1;30m"       # Black
Red="\033[1;31m"         # Red
Green="\033[1;32m"       # 'هGreen
Yellow="\033[1;33m"      # Yellow
Blue="\033[1;34m"        # Blue
Purple="\033[1;35m"      # Purple
Cyan="\033[1;36m"        # Cyan
White="\033[1;37m"       # White
import requests 
rs=requests.session()
from time import sleep  

def slep(s,done,error,privet):
	for i in range(s):
			v=s-i
			sleep(1)
			print(White+f'\r done{White}[{Green}{done}{White}] error[{Red}{error}{White}] privet[{Yellow}{privet}{White}] sleep[{v}]    ',end='')
#done[0] error [0] privet[0] sleep[0]

done,error,privet=0,0,0

def followers():
    done,error,privet=0,0,0
    ur=f'https://i.instagram.com/api/v1/users/web_profile_info/?username={u}'
    header={
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
    'cache-control': 'max-age=0',
    'cookie': f'ig_did=37396E22-2BAA-45B4-BE12-2C138F2EE907; ig_nrcb=1; mid=Yoo2NAALAAF_bSUg9E76T9FjnyOg; datr=1w6bYk9s5Fe7mNlwoBvLzX_d; shbid="6501\{id}\0541689888481:01f73c5c447b81316667f3fef03e854ec17819127a3a7cfc708b6d6e3b1375631101f397"; shbts="1658352481\{id}\0541689888481:01f71e2280fe2389aebca035d43296bda632ccf8386b2b0d3dbc3285dce2018e676c77fc"; ds_user_id={id}; csrftoken={csrftoken}; sessionid={si}; rur="NAO/{id}\0541690144166:01f716870c4d087f0dc86549dd21ad03c1b4a998a97bce93ceda73f7ddfef603bcf6b03a"',
    'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'none',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1 Instagram 231.0.0.18.113',
    'x-frame-options': 'SAMEORIGIN'
    }
    req=requests.get(ur,headers=header)
    Id = str(req.json()['data']['user']['id'])
    



    url=f'https://i.instagram.com/api/v1/friendships/{Id}/followers/?count=1000'

    
    headers={
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
    'cache-control': 'max-age=0',
    'cookie': f'ig_did=37396E22-2BAA-45B4-BE12-2C138F2EE907; ig_nrcb=1; mid=Yoo2NAALAAF_bSUg9E76T9FjnyOg; datr=1w6bYk9s5Fe7mNlwoBvLzX_d; ds_user_id={id}; shbid="6501\{id}\0541690153954:01f73336d2f16eae237610a06f5bcd1f504113d2f3f5a8272e7a3632b1c49a2b38d996b8"; shbts="1658617954\{id}\0541690153954:01f7daef559297f48fade12c799d37d559c1714e6d5f1c748d113e3afe054482d99ce705"; csrftoken={csrftoken}; sessionid={si}; rur="NAO\{id}\0541690220317:01f7a8da6b0e6b43e92dfc93007569e40f9e2e1b878df993fcb2864254ddd65cdb5e7daf"',
    'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'none',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1 Instagram 231.0.0.18.113',
    'x-frame-options': 'SAMEORIGIN'
    }
    req=requests.get(url,headers=headers)
    r=req.text
    print('\n'*3)
    print('   ====== started ======')
    print('\n'*3)

    for i in range(1,1000):
            global s
            slep(s,done,error,privet)
            sleep(s)
            a=r.split('"username"')[i]
            b=a.split('","')[0]
            c=b.split(':"')[1]
            
            
            ur=f'https://i.instagram.com/api/v1/users/web_profile_info/?username={c}'
            header={
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
            'cache-control': 'max-age=0',
            'cookie': f'ig_did=37396E22-2BAA-45B4-BE12-2C138F2EE907; ig_nrcb=1; mid=Yoo2NAALAAF_bSUg9E76T9FjnyOg; datr=1w6bYk9s5Fe7mNlwoBvLzX_d; shbid="6501\{id}\0541689888481:01f73c5c447b81316667f3fef03e854ec17819127a3a7cfc708b6d6e3b1375631101f397"; shbts="1658352481\{id}\0541689888481:01f71e2280fe2389aebca035d43296bda632ccf8386b2b0d3dbc3285dce2018e676c77fc"; ds_user_id={id}; csrftoken={csrftoken}; sessionid={si}; rur="NAO/{id}\0541690144166:01f716870c4d087f0dc86549dd21ad03c1b4a998a97bce93ceda73f7ddfef603bcf6b03a"',
            'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'none',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1 Instagram 231.0.0.18.113',
            'x-frame-options': 'SAMEORIGIN'
            }
            req=requests.get(ur,headers=header)
            Id = str(req.json()['data']['user']['id'])
            if req.json()['data']['user']['is_private']==True:
            	privet=privet+1
    
            url = f'https://i.instagram.com/api/v1/web/friendships/{Id}/follow/'
            headers={
                'accept': '*/*',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
            'content-length':'0',
            'content-type': 'application/x-www-form-urlencoded',
            'cookie': f'ig_did=37396E22-2BAA-45B4-BE12-2C138F2EE907; ig_nrcb=1; mid=Yoo2NAALAAF_bSUg9E76T9FjnyOg; datr=1w6bYk9s5Fe7mNlwoBvLzX_d; shbid="6501\{id}\0541693303457:01f7c10471212f1d54dda0b4a6d816503a605039851be4740f77fd08bfcad0fd18491eaf"; shbts="1661767457\{id}\0541693303457:01f79160db86ce66cfcfe5316271fe87fd519135a14e442fdd78efa54e9d25beb0634ab5"; csrftoken=gmzL59SsdohJitq78RKPRimb9CirRCAV; ds_user_id={id}; sessionid={si}; rur="LDC\{id}\0541693487473:01f71cb62e82739aa0b304226242da5232af191eb8b087cfb6383f1b3b210a96eb378b1b"',
            'origin': 'https://www.instagram.com',
            'referer': 'https://www.instagram.com/',
            'sec-ch-ua': '"Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1 Instagram 231.0.0.18.113',
            'x-asbd-id': '198387',
            'x-csrftoken': 'gmzL59SsdohJitq78RKPRimb9CirRCAV',
            'x-frame-options': 'SAMEORIGIN',
            'x-ig-app-id': '936619743392459',
            'x-ig-www-claim': 'hmac.AR0CTssDFfvaLymrF2w77U_v94Xm9xDN1zVkcHJhaK2vaJfy',
            'x-instagram-ajax': '1006124192'
            }
            
            a=requests.post(url,headers=headers).text
            
            if 'ok' in a:
                done=done+1
                s=j
            else:
                s=1000
                error=error+1






def following():
    done,error,privet=0,0,0
    ur=f'https://i.instagram.com/api/v1/users/web_profile_info/?username={u}'
    header={
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
    'cache-control': 'max-age=0',
    'cookie': f'ig_did=37396E22-2BAA-45B4-BE12-2C138F2EE907; ig_nrcb=1; mid=Yoo2NAALAAF_bSUg9E76T9FjnyOg; datr=1w6bYk9s5Fe7mNlwoBvLzX_d; shbid="6501\{id}\0541689888481:01f73c5c447b81316667f3fef03e854ec17819127a3a7cfc708b6d6e3b1375631101f397"; shbts="1658352481\{id}\0541689888481:01f71e2280fe2389aebca035d43296bda632ccf8386b2b0d3dbc3285dce2018e676c77fc"; ds_user_id={id}; csrftoken={csrftoken}; sessionid={si}; rur="NAO/{id}\0541690144166:01f716870c4d087f0dc86549dd21ad03c1b4a998a97bce93ceda73f7ddfef603bcf6b03a"',
    'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'none',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1 Instagram 231.0.0.18.113',
    'x-frame-options': 'SAMEORIGIN'
    }
    req=requests.get(ur,headers=header)
    Id = str(req.json()['data']['user']['id'])
    



    url=f'https://i.instagram.com/api/v1/friendships/{Id}/followers/?count=1000'

    
    headers={
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
    'cache-control': 'max-age=0',
    'cookie': f'ig_did=37396E22-2BAA-45B4-BE12-2C138F2EE907; ig_nrcb=1; mid=Yoo2NAALAAF_bSUg9E76T9FjnyOg; datr=1w6bYk9s5Fe7mNlwoBvLzX_d; ds_user_id={id}; shbid="6501\{id}\0541690153954:01f73336d2f16eae237610a06f5bcd1f504113d2f3f5a8272e7a3632b1c49a2b38d996b8"; shbts="1658617954\{id}\0541690153954:01f7daef559297f48fade12c799d37d559c1714e6d5f1c748d113e3afe054482d99ce705"; csrftoken={csrftoken}; sessionid={si}; rur="NAO\{id}\0541690220317:01f7a8da6b0e6b43e92dfc93007569e40f9e2e1b878df993fcb2864254ddd65cdb5e7daf"',
    'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'none',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1 Instagram 231.0.0.18.113',
    'x-frame-options': 'SAMEORIGIN'
    }
    req=requests.get(url,headers=headers)
    r=req.text
    print('\n'*3)
    print('   ====== started ======')
    print('\n'*3)

    for i in range(1,1000):
        
            a=r.split('"username"')[i]
            b=a.split('","')[0]
            c=b.split(':"')[1]
            
            
            global s
            slep(s,done,error,privet)
            sleep(s)
            
            
            ur=f'https://i.instagram.com/api/v1/users/web_profile_info/?username={c}'
            header={
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
            'cache-control': 'max-age=0',
            'cookie': f'ig_did=37396E22-2BAA-45B4-BE12-2C138F2EE907; ig_nrcb=1; mid=Yoo2NAALAAF_bSUg9E76T9FjnyOg; datr=1w6bYk9s5Fe7mNlwoBvLzX_d; shbid="6501\{id}\0541689888481:01f73c5c447b81316667f3fef03e854ec17819127a3a7cfc708b6d6e3b1375631101f397"; shbts="1658352481\{id}\0541689888481:01f71e2280fe2389aebca035d43296bda632ccf8386b2b0d3dbc3285dce2018e676c77fc"; ds_user_id={id}; csrftoken={csrftoken}; sessionid={si}; rur="NAO/{id}\0541690144166:01f716870c4d087f0dc86549dd21ad03c1b4a998a97bce93ceda73f7ddfef603bcf6b03a"',
            'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'none',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1 Instagram 231.0.0.18.113',
            'x-frame-options': 'SAMEORIGIN'
            }
            req=requests.get(ur,headers=header)
            Id = str(req.json()['data']['user']['id'])
            if req.json()['data']['user']['is_private']==True:
            	privet=privet+1
    
            url = f'https://i.instagram.com/api/v1/web/friendships/{Id}/follow/'
            headers={
                'accept': '*/*',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
            'content-length':'0',
            'content-type': 'application/x-www-form-urlencoded',
            'cookie': f'ig_did=37396E22-2BAA-45B4-BE12-2C138F2EE907; ig_nrcb=1; mid=Yoo2NAALAAF_bSUg9E76T9FjnyOg; datr=1w6bYk9s5Fe7mNlwoBvLzX_d; shbid="6501\{id}\0541693303457:01f7c10471212f1d54dda0b4a6d816503a605039851be4740f77fd08bfcad0fd18491eaf"; shbts="1661767457\{id}\0541693303457:01f79160db86ce66cfcfe5316271fe87fd519135a14e442fdd78efa54e9d25beb0634ab5"; csrftoken=gmzL59SsdohJitq78RKPRimb9CirRCAV; ds_user_id={id}; sessionid={si}; rur="LDC\{id}\0541693487473:01f71cb62e82739aa0b304226242da5232af191eb8b087cfb6383f1b3b210a96eb378b1b"',
            'origin': 'https://www.instagram.com',
            'referer': 'https://www.instagram.com/',
            'sec-ch-ua': '"Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1 Instagram 231.0.0.18.113',
            'x-asbd-id': '198387',
            'x-csrftoken': 'gmzL59SsdohJitq78RKPRimb9CirRCAV',
            'x-frame-options': 'SAMEORIGIN',
            'x-ig-app-id': '936619743392459',
            'x-ig-www-claim': 'hmac.AR0CTssDFfvaLymrF2w77U_v94Xm9xDN1zVkcHJhaK2vaJfy',
            'x-instagram-ajax': '1006124192'
            }
            
            a=requests.post(url,headers=headers).text
            
            if 'ok' in a:
                done=done+1
                s=j
            else:
                s=1000
                error=error+1
            
            












def unfollow_all():
    done,error,privet=0,0,0
    ur=f'https://i.instagram.com/api/v1/users/web_profile_info/?username={username}'
    header={
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
    'cache-control': 'max-age=0',
    'cookie': f'ig_did=37396E22-2BAA-45B4-BE12-2C138F2EE907; ig_nrcb=1; mid=Yoo2NAALAAF_bSUg9E76T9FjnyOg; datr=1w6bYk9s5Fe7mNlwoBvLzX_d; shbid="6501\{id}\0541689888481:01f73c5c447b81316667f3fef03e854ec17819127a3a7cfc708b6d6e3b1375631101f397"; shbts="1658352481\{id}\0541689888481:01f71e2280fe2389aebca035d43296bda632ccf8386b2b0d3dbc3285dce2018e676c77fc"; ds_user_id={id}; csrftoken={csrftoken}; sessionid={si}; rur="NAO/{id}\0541690144166:01f716870c4d087f0dc86549dd21ad03c1b4a998a97bce93ceda73f7ddfef603bcf6b03a"',
    'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'none',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1 Instagram 231.0.0.18.113',
    'x-frame-options': 'SAMEORIGIN'
    }
    req=requests.get(ur,headers=header)
    Id = str(req.json()['data']['user']['id'])
    



    url=f'https://i.instagram.com/api/v1/friendships/{Id}/following/?count=1000'

    
    headers={
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
    'cache-control': 'max-age=0',
    'cookie': f'ig_did=37396E22-2BAA-45B4-BE12-2C138F2EE907; ig_nrcb=1; mid=Yoo2NAALAAF_bSUg9E76T9FjnyOg; datr=1w6bYk9s5Fe7mNlwoBvLzX_d; ds_user_id={id}; shbid="6501\{id}\0541690153954:01f73336d2f16eae237610a06f5bcd1f504113d2f3f5a8272e7a3632b1c49a2b38d996b8"; shbts="1658617954\{id}\0541690153954:01f7daef559297f48fade12c799d37d559c1714e6d5f1c748d113e3afe054482d99ce705"; csrftoken={csrftoken}; sessionid={si}; rur="NAO\{id}\0541690220317:01f7a8da6b0e6b43e92dfc93007569e40f9e2e1b878df993fcb2864254ddd65cdb5e7daf"',
    'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'none',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1 Instagram 231.0.0.18.113',
    'x-frame-options': 'SAMEORIGIN'
    }
    req=requests.get(url,headers=headers)
    r=req.text
    print('\n'*3)
    print('   ====== started ======')
    print('\n'*3)

    for i in range(1,1000):
        
            a=r.split('"username"')[i]
            b=a.split('","')[0]
            c=b.split(':"')[1]
            
            
            global s
            slep(s,done,error,privet)
            
            sleep(s)
            
            ur=f'https://i.instagram.com/api/v1/users/web_profile_info/?username={c}'
            header={
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
            'cache-control': 'max-age=0',
            'cookie': f'ig_did=37396E22-2BAA-45B4-BE12-2C138F2EE907; ig_nrcb=1; mid=Yoo2NAALAAF_bSUg9E76T9FjnyOg; datr=1w6bYk9s5Fe7mNlwoBvLzX_d; shbid="6501\{id}\0541689888481:01f73c5c447b81316667f3fef03e854ec17819127a3a7cfc708b6d6e3b1375631101f397"; shbts="1658352481\{id}\0541689888481:01f71e2280fe2389aebca035d43296bda632ccf8386b2b0d3dbc3285dce2018e676c77fc"; ds_user_id={id}; csrftoken={csrftoken}; sessionid={si}; rur="NAO/{id}\0541690144166:01f716870c4d087f0dc86549dd21ad03c1b4a998a97bce93ceda73f7ddfef603bcf6b03a"',
            'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'none',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1 Instagram 231.0.0.18.113',
            'x-frame-options': 'SAMEORIGIN'
            }
            req=requests.get(ur,headers=header)
            Id = str(req.json()['data']['user']['id'])
            if req.json()['data']['user']['is_private']==True:
            	privet=privet+1
            
            url = f'https://i.instagram.com/api/v1/web/friendships/{Id}/unfollow/'
            headers={
                'accept': '*/*',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
            'content-length':'0',
            'content-type': 'application/x-www-form-urlencoded',
            'cookie': f'ig_did=37396E22-2BAA-45B4-BE12-2C138F2EE907; ig_nrcb=1; mid=Yoo2NAALAAF_bSUg9E76T9FjnyOg; datr=1w6bYk9s5Fe7mNlwoBvLzX_d; shbid="6501\{id}\0541693303457:01f7c10471212f1d54dda0b4a6d816503a605039851be4740f77fd08bfcad0fd18491eaf"; shbts="1661767457\{id}\0541693303457:01f79160db86ce66cfcfe5316271fe87fd519135a14e442fdd78efa54e9d25beb0634ab5"; csrftoken=gmzL59SsdohJitq78RKPRimb9CirRCAV; ds_user_id={id}; sessionid={si}; rur="LDC\{id}\0541693487473:01f71cb62e82739aa0b304226242da5232af191eb8b087cfb6383f1b3b210a96eb378b1b"',
            'origin': 'https://www.instagram.com',
            'referer': 'https://www.instagram.com/',
            'sec-ch-ua': '"Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1 Instagram 231.0.0.18.113',
            'x-asbd-id': '198387',
            'x-csrftoken': 'gmzL59SsdohJitq78RKPRimb9CirRCAV',
            'x-frame-options': 'SAMEORIGIN',
            'x-ig-app-id': '936619743392459',
            'x-ig-www-claim': 'hmac.AR0CTssDFfvaLymrF2w77U_v94Xm9xDN1zVkcHJhaK2vaJfy',
            'x-instagram-ajax': '1006124192'
            }
            
            a=requests.post(url,headers=headers).text
           
            if 'ok' in a:
                done=done+1
                s=j
            else:
                s=1000
                error=error+1
            
            
            



print(Red+f'''
{Yellow}
IG {Purple}: FX_PY3{Yellow}
TG {Purple}: FX_PY
{Red}
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⠙⠻⢶⣄⡀⠀⠀⠀⢀⣤⠶⠛⠛⡇⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣇⠀⠀⣙⣿⣦⣤⣴⣿⣁⠀⠀⣸⠇⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣡⣾⣿⣿⣿⣿⣿⣿⣿⣷⣌⠋⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣷⣄⡈⢻⣿⡟⢁⣠⣾⣿⣦⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⠘⣿⠃⣿⣿⣿⣿⡏⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⠈⠛⣰⠿⣆⠛⠁⠀⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⣦⠀⠘⠛⠋⠀⣴⣿⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣶⣾⣿⣿⣿⣿⡇⠀⠀⠀⢸⣿⣏⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣠⣶⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠀⠀⠀⠾⢿⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⣿⣿⣿⣿⣿⣿⡿⠟⠋⣁⣠⣤⣤⡶⠶⠶⣤⣄⠈⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢰⣿⣿⣮⣉⣉⣉⣤⣴⣶⣿⣿⣋⡥⠄⠀⠀⠀⠀⠉⢻⣄⠀⠀⠀⠀⠀
⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⣋⣁⣤⣀⣀⣤⣤⣤⣤⣄⣿⡄⠀⠀⠀⠀
⠀⠀⠀⠀⠙⠿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠛⠋⠉⠁⠀⠀⠀⠀⠈⠛⠃⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀


{Red}[{White}1{Red}]{Yellow} - Of Followers
{Red}[{White}2{Red}]{Yellow} - Of Following
{Red}[{White}3{Red}]{Yellow} - Unfollow All 
{White}[{Red}99{White}]{Yellow} - Exit
''')
print(White+f'\n\n= = = = = ={Yellow}  Choose  {White}= = = = = = ')
try :
	c=int(input(f'{Red}[{Yellow}+{Red}]{White} Choose : {White}'))
except :
	print('enter numper ! ')
	exit()
if c == 99:
	exit()
print(White+f'\n\n= = = = = ={Yellow}  Login Your Acc  {White}= = = = = = ')
username = input(f'{Red}[{Yellow}+{Red}]{White} Your  Username : {White}')
password = input(f'{Red}[{Yellow}+{Red}]{White} Your  Password : {White}')
s=int(input(f'{Red}[{Yellow}+{Red}]{White} Sleep : {White} '))
j=s
url = 'https://www.instagram.com/accounts/login/ajax/'
headers = {
     'accept': '*/*',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'ar,en-US;q=0.9,en;q=0.8',
    'content-length': '275',
    'content-type': 'application/x-www-form-urlencoded',
    'cookie': 'csrftoken=DqBQgbH1p7xEAaettRA0nmApvVJTi1mR; ig_did=C3F0FA00-E82D-41C4-99E9-19345C41EEF2; mid=X8DW0gALAAEmlgpqxmIc4sSTEXE3; ig_nrcb=1',
    'origin': 'https://www.instagram.com',
    'referer': 'https://www.instagram.com/',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'user-agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Mobile Safari/537.36',
    'x-csrftoken': 'DqBQgbH1p7xEAaettRA0nmApvVJTi1mR',
    'x-ig-app-id': '936619743392459',
    'x-ig-www-claim': '0',
    'x-instagram-ajax': 'bc3d5af829ea',
    'x-requested-with': 'XMLHttpRequest'
    }
data = {
         'username': f'{username}',
         'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:1589682409:{password}',
         'queryParams': '{}',
         'optIntoOneTap': 'false'
    }    
r = rs.post(url, headers=headers, data=data)
if  'authenticated":true' in r.text or 'userId' in r.text:
    csrftoken=r.cookies['csrftoken']
    si=r.cookies['sessionid']
    id=r.cookies['ds_user_id']
if c == 1:
	print(White+f'\n\n= = = = = ={Yellow}  Username  {White}= = = = = = ')
	u=input(f'{Red}[{Yellow}+{Red}]{White} Username : {White}')
	followers()
elif c == 2 :
	print('\n\n= = = = = =  Username  = = = = = = ')
	u=input(f'{Red}[{Yellow}+{Red}]{White} Username : {White}')
	following()
elif c == 3 :
	unfollow_all()
