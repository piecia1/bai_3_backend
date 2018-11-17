# bai_3_backend
set FLASK_APP=hasla.py
set FLASK_ENV=development
flask run<br />
http://127.0.0.1:5000/Ps11.php - dodanie nowego użytkownika login oraz hasło przez basic auth<br />
http://127.0.0.1:5000/Ps12.php - Formularz I, przeslanie loginu przez basic auth, zwracana maska<br />
http://127.0.0.1:5000/Ps13.php - Formularz II, przeslanie loginu oraz hasla cząstkowego(zgodnego z maska) przez basic auth, zwracany token<br />
http://127.0.0.1:5000/Ps14.php - Formularz III, zmiana hasla, login oraz stare haslo przez basic auth, token headers.Authentication, nowe haslo jako jason {"new_password":"tu_nowe_haslo"}<br />
http://127.0.0.1:5000/Ps15.php?par=5 - Formularz IV zmiana parametru block_after, login przez basic auth, 
token headers.Authentication<br />
