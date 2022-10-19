from flask_app.config.mysqlconnection import connectToMySQL

from flask import flash #flash es el encargado de mostrar mensajes/errores
import re #Importando las expresiones regulares
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$') #Expresion regular de email

class User:

    def __init__(self, data):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']

    @staticmethod
    def valida_usuario(formulario):
        is_valid = True

        if len(formulario['first_name']) < 3:
            flash('Nombre debe tener al menos 3 caracteres', 'registro')
            is_valid = False

        if len(formulario['last_name']) < 3:
            flash('Nombre debe tener al menos 3 caracteres', 'registro')
            is_valid = False
        
        if len(formulario['password']) < 6:
            flash('Su password debe tener al menos 6 caracteres', 'registro')
            is_valid = False

        if formulario['password'] != formulario['confirm_password']:
            flash('Contraseñas NO coinciden', 'registro')
            is_valid = False

        if not EMAIL_REGEX.match(formulario['email']):
            flash('E-mail inválido', 'registro')
            is_valid = False
        
        query = "SELECT * FROM users WHERE email = %(email)s"
        results = connectToMySQL('esquema_muro_privado').query_db(query, formulario)
        if len(results) >= 1:
            flash('E-mail registrado previamente', 'registro')
            is_valid = False

        return is_valid

    @classmethod
    def save(cls, formulario):
        query = "INSERT INTO users (first_name, last_name, email, password) VALUE (%(first_name)s, %(last_name)s, %(email)s,%(password)s)"
        result = connectToMySQL('esquema_muro_privado').query_db(query, formulario)
        return result

    @classmethod
    def get_by_email(cls, formulario):
        #formulario = {email: elena@codingdojo.com, password: 123}
        query = "SELECT * FROM users WHERE email = %(email)s"
        result = connectToMySQL('esquema_muro_privado').query_db(query, formulario) #SELECT me regresa una lista
        if len(result) < 1: #Significa que mi lista está vacía, entonces NO existe ese email
            return False
        else:
            #Me regresa una lista con UN registro, correspondiente al usuario de ese email
            #result = [
            #    {id: 1, first_name: elena, last_name:de troya.....} -> POSICION 0
            #]
            user = cls(result[0]) #User( {id: 1, first_name: elena, last_name:de troya.....})
            return user

    @classmethod
    def get_by_id(cls, formulario):
        #formulario = {id: 1}
        query = "SELECT * FROM users WHERE id = %(id)s"
        result = connectToMySQL('esquema_muro_privado').query_db(query, formulario)
        #result = [
        #    {id: 1, first_name: elena, last_name:de troya.....} -> POSICION 0
        #]
        user = cls(result[0]) #Creamos una instancia de User
        return user

    @classmethod
    def get_all(cls):
        query = "SELECT * FROM users ORDER BY first_name ASC"
        results = connectToMySQL('esquema_muro_privado').query_db(query) #Regresa una lista de diccionarios
        #results = [
        #   {id: 1, first_name: elena, last_name: de troya........}
        #   {id: 2, first_name: juana, last_name: de arco........}
        #]
        users = []
        for user in results:
            #user = {id: 1, first_name: elena, last_name: de troya........}
            users.append(cls(user)) #1.- cls(user) crea una instancia en base a el diccionario. "Se hace un objeto de usuario" 2.- users.append Agregando esa instancia a la lista users, user.first_name, user.last_neme -user['first_name']

        return users