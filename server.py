from flask_app import app

#Impotar controlador
from flask_app.controllers import users_controller
from flask_app.controllers import messages_controller





if __name__=="__main__":
    app.run(debug=True)