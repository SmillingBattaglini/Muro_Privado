from flask import render_template, redirect, request, session, flash
from flask_app import app

#Importamos Modelo
from flask_app.models.users import User
from flask_app.models.messages import Message

#Importación de Bcrypt
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    if not User.valida_usuario(request.form):
        return redirect('/')
    pwd = bcrypt.generate_password_hash(request.form['password']) #Encriptando la contraseña del usuario y guardándola en pwd
    # request.form['password']= pwd
    formulario = {
        "first_name": request.form['first_name'],
        "last_name": request.form['last_name'],
        "email": request.form['email'],
        "password": pwd
    }
    id =User.save(formulario)

    session['user_id'] = id

    return redirect('/dashboard')

@app.route('/login', methods=['POST'])
def login():
    #Verificamos que el email exista en la Base de datos
    user = User.get_by_email(request.form) #Recibimos una instancia de usuario O False

    if not user: #Si user = False
        flash('E-mail no encontrado', 'login')
        return redirect('/')

    #user es una instancia con todos los datos de mi usuario
    if not bcrypt.check_password_hash(user.password, request.form['password']):
        flash('Password incorrecto', 'login')
        return redirect('/')

    session['user_id'] = user.id
    return redirect('/dashboard')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')

    #Yo sé que en sesión tengo el id de mi usuario (session['user_id'])
    #Queremos una función que en base a ese id me regrese una instancia del usuario
    formulario = {"id": session['user_id']}

    user = User.get_by_id(formulario) #Recibo la instancia de usuario en base a su ID
    messages = Message.get_user_messages(formulario)

    #Lista con todos los mensajes que el usuario recibió, y una lista con todos los usuarios
    todos_usuarios = User.get_all()
    return render_template('dashboard.html', user=user, todos_usuarios=todos_usuarios, messages=messages)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


