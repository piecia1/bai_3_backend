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

            """ 
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
            """