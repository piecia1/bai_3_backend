"""Dodawanie nowych użytkowników wersja z algorytmem Shamira
"""
@app.route('/Ps11.php', methods=['GET'])
@cross_origin(origin='*')
def check_hash():
    password = 'rudy102'
    P=[]
    for i in password:
        P.append(ord(i))
    
    K = secrets.randbits(32) #klucz
    #K=1732426912
    N=5 #liczba znakow

    R=[]
    for i in range(0,N-1):
        R.append(secrets.randbits(32))
    
    #R=[1133272513, 3880634564]
    #b=K

    y=[]
    y_i=K
 
    
    for i in range(1,len(password)+1):
        y_i=K
        for x in range(0,N-1):
            y_i+=R[x]*pow(i,x+1)
        y.append(y_i)
    
    

    s=[]
    for y_i,P_i in zip(y,P):
        s.append(y_i-P_i)

    

    # Liczby 1, 3, 4, 6
    numbers=[1,2,3,4,5]
    chars=[ord('r'),ord('u'),ord('d'),ord('y'),ord('1')]
    y1=[]
    for number,char in zip(numbers,chars):
        y1.append(s[number-1]+char)
    
    # Obliczanie K'
    K_1=0
    for i,y_i in zip(numbers,y1):
        licznik=1
        mianownik=1
        for liczba in numbers:
            if(i==liczba):
                continue
            else:
                licznik*=liczba
                mianownik*=(i-liczba)
        K_1+=y_i*(licznik/mianownik)

    return jsonify({'Klucz':K,'Klucz1':K_1})

    #############################################################################################
    """Sprawdzanie loginu
"""
@app.route('/Ps20.php', methods=['GET'])
@cross_origin(origin='*')
def checkLogin():
    auth=request.authorization
    if(not auth):
        return jsonify({'info':'Nie przeslales danych do logowania uzytkownika'})
    login,password= auth.username, auth.password
    if(not login):
        return jsonify({'info':'Brak loginu'})
    con = cx_Oracle.connect(database_url)
    cur = con.cursor()
    user=checkUserByLogin4(cur,login)
    if (not user):
        return jsonify({'info':'Nieporawny login'})
    else:
        return jsonify({'Pola hasła do wstawienia':user[8]})
    return jsonify(login)

    #########################################################################################
    """Sprawdzanie hasła cząstkowego
"""
@app.route('/Ps14.php', methods=['GET'])
@cross_origin(origin='*')
def checkPassword2():
    auth=request.authorization
    if(not auth):
        return jsonify({'info':'Nie przeslales danych do logowania uzytkownika'})
    login,password= auth.username, auth.password
    if(not login):
        return jsonify({'info':'Brak loginu'})
    con = cx_Oracle.connect(database_url)
    cur = con.cursor()
    user=checkUserByLogin4(cur,login)
    if (not user):
        return jsonify({'info':'Nieporawny login'})
    else:
        # Pobieramy mask_hash z tabeli mask
        bind={'user4_id':user[0], 'field_mask': user[8]}
        sql='SELECT mask_hash FROM mask WHERE user4_id=:user4_id AND field_mask=:field_mask'
        cur.prepare(sql)
        cur.execute(sql, bind)
        mask_hash = cur.fetchone()[0]
        # Hashujemy przesłane hasło
        field_password= password+user[7]
        h_filed_password=hashlib.md5(field_password.encode())
        hash_field_password=h_filed_password.hexdigest()
        #return jsonify({'mask_hash':mask_hash, 'field_password':hash_field_password})
        if(mask_hash==hash_field_password):
            return jsonify({'info':'jestes zalogowany'})
        else:
            return jsonify({'info':'Niepoprawne dane do logownia'})
    return jsonify(mask_hash)

"""Sprawdzanie hasła cząstkowego
"""
@app.route('/Ps15.php', methods=['GET'])
@cross_origin(origin='*')
def checkhash():
    auth=request.authorization
    if(not auth):
        return jsonify({'info':'Nie przeslales danych do logowania uzytkownika'})
    login,password= auth.username, auth.password
    salt=str(secrets.randbits(32))

    # hashowanie hasła
    db_password = password + salt
    h_password=hashlib.md5(db_password.encode())
    hash_password=h_password.hexdigest()
    
    #haszowanie soli
    h_salt=hashlib.md5(salt.encode())
    hash_salt=h_salt.hexdigest()

    # Laczenie dwoch haszy
    h_filed_password=hashlib.md5(password.encode())
    hash_field_password=h_filed_password.hexdigest()
    hash_password2=hash_field_password+hash_salt

    return jsonify({'hash1':hash_password,'hash2':hash_password2})

#######################################################################################################
""" Sprawdzanie poprawności hasła
"""
@app.route('/Ps13.php', methods=['GET'])
@cross_origin(origin='*')
def checkPassword():
    auth = request.authorization
    if(not auth):
        return jsonify({'info':'Nie przeslales danych do logowania'})
    login,password=auth.username, auth.password
    # dodana czesc aby nie zapisywac null
    if((not login) or (not password)):
        return jsonify({'info':'Brak loginu lub hasla'})
    con = cx_Oracle.connect(database_url)
    cur = con.cursor()
    check_user_by_login=checkUserByLogin(cur,login)
    if(not check_user_by_login):
        check_fake_user_by_login=checkFakeUserByLogin(cur,login)
        if(not check_fake_user_by_login):
            random_fields=sorted(random.sample(range(0,16),random.randint(5,8)))
            field_mask=','.join(map(str,random_fields))
            bind={'name':login,'last_failed_login':datetime.datetime.now(),'failed_attemps_login':0,'block_after':random.choice(range_values), 'maska': field_mask}
            sql='INSERT INTO fake_users4 VALUES(fake_user4_id.nextval,:name,:last_failed_login,:failed_attemps_login,:block_after,:maska)'
            cur.prepare(sql)
            cur.execute(sql,bind)
            con.commit() # zatwierdzenie operacji dodania fake_usera
            return jsonify({'info':field_mask})
        else:
            # 1 - patrzymy czy konto nie jest zablokowane
            # pobieramy liczbe prob logowan
            # oraz liczbe nieudanych logowan po ktorych nastepuje blokada konta
            bind={'name':login}
            sql='SELECT * FROM fake_users4 WHERE name=:name'
            cur.prepare(sql)
            cur.execute(sql,bind)
            failed_login=cur.fetchone()
            failed_attemps_login, block_after=failed_login[3], failed_login[4]
            if(failed_attemps_login>=block_after):
                return jsonify({'info':'Twoje konto jest zablokowane'})
            # 2 sprawdzamy czy uzytkownik moze wykonac kolejna probe logowania
            last_failed_login=failed_login[2]
            actual_time=datetime.datetime.now() 
            if (failed_attemps_login == 0):
                return jsonify({'info':failed_login[5]})
            elif (failed_attemps_login == 1):
                wait_time = last_failed_login + datetime.timedelta(seconds=10)
                wait_seconds=30
            elif(failed_attemps_login == 2):
                wait_time = last_failed_login + datetime.timedelta(seconds = 30)
                wait_seconds=60
            elif(failed_attemps_login==3):
                wait_time=last_failed_login+datetime.timedelta(minutes=1)
                wait_seconds=300
            elif(failed_attemps_login==4):
                wait_time=last_failed_login+datetime.timedelta(minutes=5)
                wait_seconds=1800
            elif(failed_attemps_login==5):
                wait_time=last_failed_login+datetime.timedelta(minutes=30)
                wait_seconds=3600
            elif(failed_attemps_login==6):
                wait_time=last_failed_login+datetime.timedelta(hours=1)
                wait_seconds=10000 #nie uzywane
            else:
                return jsonify({'info':'Twoje konto jest zablokowane'})
            if(wait_time > actual_time):
                diffrence_time = wait_time - actual_time
                return jsonify({'info' : 'Musisz poczekac','time' : diffrence_time.total_seconds()})
            else:
               return jsonify({'info':failed_login[5]})
    else:
        # 1 - patrzymy czy konto nie jest zablokowane
        # pobieramy liczbe prob logowan
        # oraz liczbe nieudanych logowan po ktorych nastepuje blokada konta
        bind={'name':login}
        sql='SELECT * FROM users4 WHERE name=:name'
        cur.prepare(sql)
        cur.execute(sql,bind)
        user_login=cur.fetchone()
        failed_attemps_login, block_after=user_login[5], user_login[6]
        if(failed_attemps_login>=block_after):
            return jsonify({'info':'Twoje konto jest zablokowane'})
        # 2 sprawdzamy czy uzytkownik moze wykonac kolejna probe logowania
        last_failed_login=user_login[4]
        actual_time=datetime.datetime.now() 
        if(failed_attemps_login == 0):
            return jsonify({'info':user_login[8]})
        elif (failed_attemps_login == 1):
            wait_time = last_failed_login + datetime.timedelta(seconds=10)
            wait_seconds=30
        elif(failed_attemps_login == 2):
            wait_time = last_failed_login + datetime.timedelta(seconds = 30)
            wait_seconds=60
        elif(failed_attemps_login==3):
            wait_time=last_failed_login+datetime.timedelta(minutes=1)
            wait_seconds=300
        elif(failed_attemps_login==4):
            wait_time=last_failed_login+datetime.timedelta(minutes=5)
            wait_seconds=1800
        elif(failed_attemps_login==5):
            wait_time=last_failed_login+datetime.timedelta(minutes=30)
            wait_seconds=3600
        elif(failed_attemps_login==6):
            wait_time=last_failed_login+datetime.timedelta(hours=1)
            wait_seconds=10000 #nie uzywane
        else:
            return jsonify({'info':'Twoje konto jest zablokowane'})
        if(wait_time > actual_time):
            diffrence_time = wait_time - actual_time
            return jsonify({'info' : 'Musisz poczekac','time' : diffrence_time.total_seconds()})
        else:
            return jsonify({'info':user_login[8]})

    
            check_user=checkUser(cur,login,password)
            if(not check_user):
                # 3 - zwiekszamy liczbe prob logowan o 1 (failed_attemps_login)
                bind={'name' : login, 'last_failed_login' : actual_time}
                sql='UPDATE users2 SET failed_attemps_login = failed_attemps_login + 1, last_failed_login=:last_failed_login WHERE name=:name'
                cur.prepare(sql)
                cur.execute(sql,bind)
                con.commit()
                failed_attemps_login=failed_attemps_login+1
                # 3 - sprawdzamy czy nie była to ostatnia próba logowania
                if(failed_attemps_login==block_after):
                    return jsonify({'info':'Twoje konto zostało zablokowane'})
                else:
                    return jsonify({'info':'Niepoprawny login lub hasło','time':wait_seconds})
            else:
                #poprawne logowanie
                bind={'name':login}
                sql='SELECT * FROM users2 WHERE name=:name'
                cur.prepare(sql)
                cur.execute(sql,bind)
                correct_user=cur.fetchone()
                bind={'name':login,'last_login':actual_time}
                sql='UPDATE users2 SET failed_attemps_login = 0,last_login=:last_login WHERE name=:name'
                cur.prepare(sql)
                cur.execute(sql,bind)
                con.commit()
                return jsonify({'name':correct_user[1],'last_login':correct_user[3],'last_failed_login':correct_user[4],
                                'failed_attemps_login':correct_user[5],'block_after':correct_user[6]})
    
###########################################################################################################
###########################################################################################################
###########################################################################################################
# -*- coding: utf-8 -*-

from flask import Flask,jsonify,json,abort
from flask import request,make_response
from flask_cors import CORS, cross_origin
import cx_Oracle
import json
import datetime
import random
import hashlib, secrets


app = Flask(__name__)
cors = CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
database_url='piecia/piecia1@localhost:1521/xe'
range_values=[3,4,5,6,7]

@app.before_request
def option_autoreply():
    """ Always reply 200 on OPTIONS request """

    if request.method == 'OPTIONS':
        resp = app.make_default_options_response()

        headers = None
        if 'ACCESS_CONTROL_REQUEST_HEADERS' in request.headers:
            headers = request.headers['ACCESS_CONTROL_REQUEST_HEADERS']

        h = resp.headers

        # Allow the origin which made the XHR
        h['Access-Control-Allow-Origin'] = request.headers['Origin']
        # Allow the actual method
        h['Access-Control-Allow-Methods'] = request.headers['Access-Control-Request-Method']
        # Allow for 10 seconds
        h['Access-Control-Max-Age'] = "10"

        h['Access-Control-Allow-Credentials'] = "true"

        # We also keep current headers
        if headers is not None:
            h['Access-Control-Allow-Headers'] = headers

        return resp


@app.after_request
def set_allow_origin(resp):
    """ Set origin for GET, POST, PUT, DELETE requests """

    h = resp.headers

    # Allow crossdomain for other HTTP Verbs
    if request.method != 'OPTIONS' and 'Origin' in request.headers:
        h['Access-Control-Allow-Origin'] = request.headers['Origin']


    return resp


"""Dodawanie nowych użytkowników wersja bez algorytmu Shamira
"""
@app.route('/Ps11.php', methods=['GET'])
@cross_origin(origin='*')
def addUser():

    # login oraz hasło 
    auth = request.authorization
    if(not auth):
        return jsonify({'info':'Nie przeslales danych do logowania'})
    
    login, password = auth.username, auth.password
    if((not login) or  (not password)):
        return jsonify({'info':'Brak loginu lub hasła'})
    #połączenie z bazą
    con = cx_Oracle.connect(database_url)
    cur = con.cursor()

    check_login=checkUserByLogin(cur,login)
    if(check_login):
        return jsonify({'info':'Użytkownik istnieje już w bazie danych'})
    #sprawdzenie długości hasła
    if( (len(password) < 8) or (len(password)> 16) ):
        return jsonify({'info':'Nieprawidłowa długość hasła'})
    
    # sól
    salt=str(secrets.randbits(32))
    
    # hashowanie hasła
    db_password = password + salt
    h_password=hashlib.md5(db_password.encode())
    hash_password=h_password.hexdigest()

    #połączenie z bazą
    con = cx_Oracle.connect(database_url)
    cur = con.cursor()

    #Dodanie użytkownika
    bind={'name':login,'password':hash_password,'last_login':datetime.datetime.now(),'last_failed_login':datetime.datetime(1,1,1,1,1,1),
          'failed_attemps_login':0,'block_after':5,'salt':salt, 'last_mask':None, 'token':None}
    sql='INSERT INTO users4 VALUES(user4_id.nextval,:name,:password,:last_login,:last_failed_login,:failed_attemps_login,:block_after,:salt, :last_mask, :token)'
    cur.prepare(sql)
    cur.execute(sql,bind)
    con.commit() 

    #Sprawdzenie id użtkownika
    bind={'name':login}
    sql='SELECT user4_id FROM users4 WHERE name=:name'
    cur.prepare(sql)
    cur.execute(sql,bind)
    user4_id=cur.fetchone()[0]
    
    #Dodanie 10 masek hasła, bez sprawdzenia czy maski sie nie powtarzaja
    
    #losuje liczbe int z zakresu <4,password/2>
    numbers_field=random.randint(4,int(len(password)/2))
    #towrze liste z liczbami z zakresu <0,password-1>
    range_password=list(range(len(password)))

    check_random_fields=[]
    i=0
    while (i <10 ):   
        field_password=''
        random_fields=sorted(random.sample(range_password,numbers_field)) #Wybieram numbers_field liczb z zakresu range_password
        if(random_fields in check_random_fields):
            continue
        check_random_fields.append(random_fields)
        for field in random_fields:
            field_password += password[field]     
        #uzycie , aby uniknąć sytuacji 11113 -> 1,11,13 
        field_mask=','.join(map(str,random_fields))
        #hashowanie hasła
        field_password += salt
        h_mask=hashlib.md5(field_password.encode())
        hash_mask=h_mask.hexdigest()
        #dodanie maski
        bind={'user4_id':user4_id, 'mask_hash': hash_mask, 'field_mask':field_mask}
        sql='INSERT INTO mask VALUES(mask_id.nextval,:user4_id,:mask_hash,:field_mask)'
        cur.prepare(sql)
        cur.execute(sql,bind)
        con.commit() #
        i += 1  

    # uaktualnienie maski hasła użytkownika
    bind={'last_mask': field_mask, 'user4_id':user4_id}
    sql='UPDATE users4 SET last_mask=:last_mask WHERE user4_id=:user4_id'
    cur.prepare(sql)
    cur.execute(sql,bind)
    con.commit() 
    
    
    cur.close()
    con.close()
    return jsonify({'info' : 'Dodano nowego użytkownika'})


"""Formularz I
Sprawdzanie loginu
"""
@app.route('/Ps12.php', methods=['GET'])
@cross_origin(origin='*')
def login():
    auth = request.authorization
    if(not auth):
        return jsonify({'info':'Nie przeslales danych do logowania'})
    login=auth.username
    # Sprawdzamy czy przesłany został login
    if(not login):
        return jsonify({'info':'Brak loginu'})
    con = cx_Oracle.connect(database_url)
    cur = con.cursor()
    check_user_by_login=checkUserByLogin(cur,login)
    if(not check_user_by_login):
        check_fake_user_by_login=checkFakeUserByLogin(cur,login)
        if(not check_fake_user_by_login):
            random_fields=sorted(random.sample(range(0,16),random.randint(5,8)))
            field_mask=','.join(map(str,random_fields))
            bind={'name':login,'last_failed_login':datetime.datetime.now(),'failed_attemps_login':0,'block_after':random.choice(range_values), 'maska': field_mask}
            sql='INSERT INTO fake_users4 VALUES(fake_user4_id.nextval,:name,:last_failed_login,:failed_attemps_login,:block_after,:maska)'
            cur.prepare(sql)
            cur.execute(sql,bind)
            con.commit() # zatwierdzenie operacji dodania fake_usera
            return jsonify({'info': 'Podaj hasło', 'maska':field_mask})
        else:
            # 1 - patrzymy czy konto nie jest zablokowane
            # pobieramy liczbe prob logowan
            # oraz liczbe nieudanych logowan po ktorych nastepuje blokada konta
            bind={'name':login}
            sql='SELECT * FROM fake_users4 WHERE name=:name'
            cur.prepare(sql)
            cur.execute(sql,bind)
            failed_login=cur.fetchone()
            failed_attemps_login, block_after=failed_login[3], failed_login[4]
            if(failed_attemps_login>=block_after):
                return jsonify({'info':'Twoje konto jest zablokowane'})
            # 2 sprawdzamy czy uzytkownik moze wykonac kolejna probe logowania
            last_failed_login=failed_login[2]
            actual_time=datetime.datetime.now() 
            if (failed_attemps_login == 0):
                return jsonify({'info': 'Podaj hasło','maska':failed_login[5]})
            elif (failed_attemps_login == 1):
                wait_time = last_failed_login + datetime.timedelta(seconds=10)
                wait_seconds=30
            elif(failed_attemps_login == 2):
                wait_time = last_failed_login + datetime.timedelta(seconds = 30)
                wait_seconds=60
            elif(failed_attemps_login==3):
                wait_time=last_failed_login+datetime.timedelta(minutes=1)
                wait_seconds=300
            elif(failed_attemps_login==4):
                wait_time=last_failed_login+datetime.timedelta(minutes=5)
                wait_seconds=1800
            elif(failed_attemps_login==5):
                wait_time=last_failed_login+datetime.timedelta(minutes=30)
                wait_seconds=3600
            elif(failed_attemps_login==6):
                wait_time=last_failed_login+datetime.timedelta(hours=1)
                wait_seconds=10000 #nie uzywane
            else:
                return jsonify({'info':'Twoje konto jest zablokowane'})
            if(wait_time > actual_time):
                diffrence_time = wait_time - actual_time
                return jsonify({'info' : 'Musisz poczekac','time' : diffrence_time.total_seconds()})
            else:
               return jsonify({'info':'Podaj hasło', 'maska':failed_login[5]})
    else:
        # 1 - patrzymy czy konto nie jest zablokowane
        # pobieramy liczbe prob logowan
        # oraz liczbe nieudanych logowan po ktorych nastepuje blokada konta
        bind={'name':login}
        sql='SELECT * FROM users4 WHERE name=:name'
        cur.prepare(sql)
        cur.execute(sql,bind)
        user_login=cur.fetchone()
        failed_attemps_login, block_after=user_login[5], user_login[6]
        if(failed_attemps_login>=block_after):
            return jsonify({'info':'Twoje konto jest zablokowane'})
        # 2 sprawdzamy czy uzytkownik moze wykonac kolejna probe logowania
        last_failed_login=user_login[4]
        actual_time=datetime.datetime.now() 
        if(failed_attemps_login == 0):
            return jsonify({'info':'Podaj hasło','maska':user_login[8]})
        elif (failed_attemps_login == 1):
            wait_time = last_failed_login + datetime.timedelta(seconds=10)
            wait_seconds=30
        elif(failed_attemps_login == 2):
            wait_time = last_failed_login + datetime.timedelta(seconds = 30)
            wait_seconds=60
        elif(failed_attemps_login==3):
            wait_time=last_failed_login+datetime.timedelta(minutes=1)
            wait_seconds=300
        elif(failed_attemps_login==4):
            wait_time=last_failed_login+datetime.timedelta(minutes=5)
            wait_seconds=1800
        elif(failed_attemps_login==5):
            wait_time=last_failed_login+datetime.timedelta(minutes=30)
            wait_seconds=3600
        elif(failed_attemps_login==6):
            wait_time=last_failed_login+datetime.timedelta(hours=1)
            wait_seconds=10000 #nie uzywane
        else:
            return jsonify({'info':'Twoje konto jest zablokowane'})
        if(wait_time > actual_time):
            diffrence_time = wait_time - actual_time
            return jsonify({'info' : 'Musisz poczekac','time' : diffrence_time.total_seconds()})
        else:
            return jsonify({'info':'Podaj hasło','maska':user_login[8]})


""" Formularz II 
Sprawdzanie poprawności hasła cząstkowego
"""
@app.route('/Ps13.php', methods=['GET'])
@cross_origin(origin='*')
def checkPassword():

    auth = request.authorization
    if(not auth):
        return jsonify({'info':'Nie przeslales danych do logowania'})
    login,password=auth.username, auth.password
    # dodana czesc aby nie zapisywac null
    if((not login) or (not password)):
        return jsonify({'info':'Brak loginu lub hasla'})
    
    con = cx_Oracle.connect(database_url)
    cur = con.cursor()
    user=checkUserByLogin4(cur,login)
    #Jeżeli nie jest to użytkownik zarejstrowany więc musi to być fejkowy użytkownik (fake_user)
    if (not user):
        fake_user=checkFakeUserByLogin4(cur,login)
        actual_time = datetime.datetime.now() 
        failed_attemps_login = fake_user[3]
        block_after = fake_user[4]
        # 1 - patrzymy czy konto nie jest zablokowane
        # pobieramy liczbe prob logowan
        # oraz liczbe nieudanych logowan po ktorych nastepuje blokada konta
        if(failed_attemps_login>=block_after):
            return jsonify({'info':'Twoje konto jest zablokowane'})
        # 2 sprawdzamy czy uzytkownik moze wykonac kolejna probe logowania
        last_failed_login=fake_user[2]
        actual_time=datetime.datetime.now() 
        if (failed_attemps_login == 0):
            # 3 - zwiekszamy liczbe prob logowan o 1 (failed_attemps_login)
            # Nie ma ograniczenia czasowego
            bind={'name' : login, 'last_failed_login' : actual_time}
            sql='UPDATE fake_users4 SET failed_attemps_login = failed_attemps_login + 1, last_failed_login=:last_failed_login WHERE name=:name'
            cur.prepare(sql)
            cur.execute(sql,bind)
            con.commit()
            return jsonify({'info':'Niepoprawny login lub hasło',})
        elif (failed_attemps_login == 1):
            wait_time = last_failed_login + datetime.timedelta(seconds=10)
            wait_seconds=30
        elif(failed_attemps_login == 2):
            wait_time = last_failed_login + datetime.timedelta(seconds = 30)
            wait_seconds=60
        elif(failed_attemps_login==3):
            wait_time=last_failed_login+datetime.timedelta(minutes=1)
            wait_seconds=300
        elif(failed_attemps_login==4):
            wait_time=last_failed_login+datetime.timedelta(minutes=5)
            wait_seconds=1800
        elif(failed_attemps_login==5):
            wait_time=last_failed_login+datetime.timedelta(minutes=30)
            wait_seconds=3600
        elif(failed_attemps_login==6):
            wait_time=last_failed_login+datetime.timedelta(hours=1)
            wait_seconds=10000 #nie uzywane
        else:
            return jsonify({'info':'Twoje konto jest zablokowane'})
        if(wait_time > actual_time):
            diffrence_time = wait_time - actual_time
            return jsonify({'info' : 'Musisz poczekac','time' : diffrence_time.total_seconds()})
        else:
            # 3 - zwiekszamy liczbe prob logowan o 1 (failed_attemps_login)
            bind={'name' : login, 'last_failed_login' : actual_time}
            sql='UPDATE fake_users4 SET failed_attemps_login = failed_attemps_login + 1, last_failed_login=:last_failed_login WHERE name=:name'
            cur.prepare(sql)
            cur.execute(sql,bind)
            con.commit()
            failed_attemps_login=failed_attemps_login+1
            # 3 - sprawdzamy czy nie była to ostatnia próba logowania
            if(failed_attemps_login>=block_after):
                return jsonify({'info':'Twoje konto zostało zablokowane'})
            else:
                return jsonify({'info':'Niepoprawny login lub hasło',})
    #Jest to użytkownik zarejestrowany
    else:
        failed_attemps_login = user[5]
        block_after = user[6]
        # 1 - patrzymy czy konto nie jest zablokowane
        if(failed_attemps_login>=block_after):
            return jsonify({'info':'Twoje konto jest zablokowane'})
        # 2 sprawdzamy czy uzytkownik moze wykonac kolejna probe logowania
        last_failed_login=user[4]
        actual_time=datetime.datetime.now() 
        if(failed_attemps_login == 0):
            #Następuje próba logowania
            # Pobieramy mask_hash z tabeli mask
            bind={'user4_id':user[0], 'field_mask': user[8]}
            sql='SELECT mask_hash FROM mask WHERE user4_id=:user4_id AND field_mask=:field_mask'
            cur.prepare(sql)
            cur.execute(sql, bind)
            mask_hash = cur.fetchone()[0]
            # Hashujemy przesłane hasło
            field_password= password+user[7]
            h_filed_password=hashlib.md5(field_password.encode())
            hash_field_password=h_filed_password.hexdigest()
            # Poprawne Haslo cząstkowe
            if(mask_hash==hash_field_password):
                token=secrets.randbits(32)
                bind = {'user4_id' : user[0]}
                sql = 'SELECT field_mask FROM mask WHERE user4_id=:user4_id'
                cur.prepare(sql)
                cur.execute(sql, bind)
                fields_masks = cur.fetchall()
                field_mask = random.choice(fields_masks)[0]#nowa maska
                bind = {'name' : login, 'last_mask' : field_mask, 'token' : token}
                sql = 'UPDATE users4 SET failed_attemps_login = 0, last_mask=:last_mask, token=:token WHERE name=:name'
                cur.prepare(sql)
                cur.execute(sql, bind)
                con.commit()
                return jsonify({'info':'Jesteś zalogownany', 'token': token})
            # Niepoprawne hasło cząstkowe
            else:
                actual_time = datetime.datetime.now() 
                failed_attemps_login = user[5]
                block_after = user[6]
                # 3 - zwiekszamy liczbe prob logowan o 1 (failed_attemps_login)
                bind={'name' : login, 'last_failed_login' : actual_time}
                sql='UPDATE users4 SET failed_attemps_login = failed_attemps_login + 1, last_failed_login=:last_failed_login WHERE name=:name'
                cur.prepare(sql)
                cur.execute(sql,bind)
                con.commit()
                return jsonify({'info':'Niepoprawne hasło',})
        elif (failed_attemps_login == 1):
            wait_time = last_failed_login + datetime.timedelta(seconds=10)
            wait_seconds=30
        elif(failed_attemps_login == 2):
            wait_time = last_failed_login + datetime.timedelta(seconds = 30)
            wait_seconds=60
        elif(failed_attemps_login==3):
            wait_time=last_failed_login+datetime.timedelta(minutes=1)
            wait_seconds=300
        elif(failed_attemps_login==4):
            wait_time=last_failed_login+datetime.timedelta(minutes=5)
            wait_seconds=1800
        elif(failed_attemps_login==5):
            wait_time=last_failed_login+datetime.timedelta(minutes=30)
            wait_seconds=3600
        elif(failed_attemps_login==6):
            wait_time=last_failed_login+datetime.timedelta(hours=1)
            wait_seconds=10000 #nie uzywane
        else:
            return jsonify({'info':'Twoje konto jest zablokowane'})
        if(wait_time > actual_time):
            diffrence_time = wait_time - actual_time
            return jsonify({'info' : 'Musisz poczekac','time' : diffrence_time.total_seconds()})
        else:
            # Pobieramy mask_hash z tabeli mask
            bind={'user4_id':user[0], 'field_mask': user[8]}
            sql='SELECT mask_hash FROM mask WHERE user4_id=:user4_id AND field_mask=:field_mask'
            cur.prepare(sql)
            cur.execute(sql, bind)
            mask_hash = cur.fetchone()[0]
            # Hashujemy przesłane hasło
            field_password= password+user[7]
            h_filed_password=hashlib.md5(field_password.encode())
            hash_field_password=h_filed_password.hexdigest()
            # Poprawne Haslo cząstkowe
            if(mask_hash==hash_field_password):
                token=secrets.randbits(32)
                bind = {'user4_id' : user[0]}
                sql = 'SELECT field_mask FROM mask WHERE user4_id=:user4_id'
                cur.prepare(sql)
                cur.execute(sql, bind)
                fields_masks = cur.fetchall()
                field_mask = random.choice(fields_masks)[0]#nowa maska
                bind = {'name' : login, 'last_mask' : field_mask, 'token' : token}
                sql = 'UPDATE users4 SET failed_attemps_login = 0, last_mask=:last_mask, token=:token WHERE name=:name'
                cur.prepare(sql)
                cur.execute(sql, bind)
                con.commit()
                return jsonify({'info':'Jesteś zalogownany', 'token': token})
            # Niepoprawne hasło cząstkowe
            else:
                actual_time = datetime.datetime.now() 
                failed_attemps_login = user[5]
                block_after = user[6]
                # 3 - zwiekszamy liczbe prob logowan o 1 (failed_attemps_login)
                bind={'name' : login, 'last_failed_login' : actual_time}
                sql='UPDATE users4 SET failed_attemps_login = failed_attemps_login + 1, last_failed_login=:last_failed_login WHERE name=:name'
                cur.prepare(sql)
                cur.execute(sql,bind)
                con.commit()
                failed_attemps_login=failed_attemps_login+1
                # 3 - sprawdzamy czy nie była to ostatnia próba logowania
                if(failed_attemps_login>=block_after):
                    return jsonify({'info':'Twoje konto zostało zablokowane'})
                else:
                    return jsonify({'info':'Niepoprawne hasło',})
    return jsonify({'info': 'Nieznany błąd'})


""" Formularz III zmiana hasła
"""
@app.route('/Ps14.php', methods=['GET', 'POST'])
@cross_origin(origin='*')
def changePassword():
    # 1 dodatkowa weryfikacja

    auth = request.authorization
    if(not auth):
        return jsonify({'info':'Nie przeslales danych do zmiany hasla'})
    login, old_password=auth.username, auth.password

    # Sprawdzenie czy stare hasło i login zostały przesłane
    if((not login) or (not old_password)):
        return jsonify({'info':'Brak loginu lub hasla'})

    # Tutaj popraw 
    
    token = request.headers.get('Authentication')
    if (type(token) != type(int())):
        return jsonify({'info' : 'Niepoprawny typ danych Authentication'})
    #return jsonify({'name':login, 'old_password':old_password, 'token':token})


    con = cx_Oracle.connect(database_url)
    cur = con.cursor()
    
    # Pobranie użytkownika
    bind={'name':login, 'token':token}
    sql='SELECT * FROM users4 WHERE name =: name AND token=:token'
    cur.prepare(sql)
    cur.execute(sql, bind)
    user = cur.fetchone()
    if(not user):
        return jsonify({'info':'Niepoprawny login lub token'})
    #Sprawdzam czy stare hasło jest poprawne
    old_salt = user[7]
    old_db_password = old_password + old_salt
    old_h_password=hashlib.md5(old_db_password.encode())
    old_hash_password=old_h_password.hexdigest()

    if(user[2] != old_hash_password):
        return jsonify({'info':'Niepoprawne stare hasło'})

    new_salt=str(secrets.randbits(32))
    data=request.get_json()
    new_password = data.get('new_password')
 
    #sprawdzenie długości hasła
    if( (len(new_password) < 8) or (len(new_password)> 16) ):
        return jsonify({'info':'Nieprawidłowa długość hasła'})

    # hashowanie hasła
    new_db_password = new_password + new_salt
    new_h_password=hashlib.md5(new_db_password.encode())
    new_hash_password=new_h_password.hexdigest()


    # Usuwam maski
    user_id = user[0]
    bind={'user4_id':user_id}
    sql='DELETE FROM mask WHERE user4_id =: user4_id'
    cur.prepare(sql)
    cur.execute(sql, bind)
    
    # Zmiana hasła
    bind={'name' : login, 'password' : new_hash_password, 'salt' : new_salt, 'last_mask' : None}
    sql='UPDATE users4 SET password=:password, salt=:salt, last_mask=:last_mask WHERE name=:name'
    cur.prepare(sql)
    cur.execute(sql,bind)
    con.commit() 
    
    #Dodanie 10 masek hasła
    numbers_field=random.randint(4,int(len(new_password)/2))
    range_password=list(range(len(new_password)))
    for i in range(10):   
        field_password=''
        random_fields=sorted(random.sample(range_password,numbers_field))
        for field in random_fields:
            field_password+=new_password[field]     
        field_mask=','.join(map(str,random_fields))
        field_password+=new_salt
        h_mask=hashlib.md5(field_password.encode())
        hash_mask=h_mask.hexdigest()
        bind={'user4_id':user_id, 'mask_hash': hash_mask, 'field_mask':field_mask}
        sql='INSERT INTO mask VALUES(mask_id.nextval,:user4_id,:mask_hash,:field_mask)'
        cur.prepare(sql)
        cur.execute(sql,bind)
        con.commit() # 

    # uaktualnienie maski hasła użytkownika
    bind={'last_mask': field_mask, 'user4_id':user_id}
    sql='UPDATE users4 SET last_mask=:last_mask WHERE user4_id=:user4_id'
    cur.prepare(sql)
    cur.execute(sql,bind)

    con.commit()
    cur.close()
    con.close()

    return jsonify({'info': 'Dokonano zmiany hasła'})



def checkUserByLogin4(cur,login):
    bind = {'login': login}
    sql = 'select * from users4 where name = :login'
    cur.prepare(sql)
    cur.execute(sql, bind)
    logged_user = cur.fetchone() 
    if(logged_user):
        return logged_user
    else:
        return False

def checkUserByLogin(cur,login):
    bind = {'login': login}
    sql = 'select * from users4 where name = :login'
    cur.prepare(sql)
    cur.execute(sql, bind)
    logged_user = cur.fetchone() 
    if(logged_user):
        return True
    else:
        return False

def checkFakeUserByLogin4(cur,login):
    bind = {'login': login}
    sql = 'select * from fake_users4 where name = :login'
    cur.prepare(sql)
    cur.execute(sql, bind)
    logged_user = cur.fetchone() 
    if(logged_user):
        return logged_user
    else:
        return False

def checkFakeUserByLogin(cur,login):
    bind = {'login': login}
    sql = 'select * from fake_users4 where name = :login'
    cur.prepare(sql)
    cur.execute(sql, bind)
    logged_user = cur.fetchone() 
    if(logged_user):
        return True
    else:
        return False

def checkUser(cur,login,password):
    bind = {'login': login,'password_check':password}
    sql = 'select * from users2 where name = :login AND password=:password_check'
    cur.prepare(sql)
    cur.execute(sql, bind)
    logged_user = cur.fetchone() 
    if(logged_user):
        return True
    else:
        return False 
"""
Pytania do tomka 
1 - Przechodzenie między formularzami - dodatkowe zabezpieczenia
2 - Sposób przesyłania hasła i loginu
3 - Token zamiast hasła - sposób przesyłania
4 - dodatkowa weryfikacja
5 - Co mam kiedy zwracać
"""