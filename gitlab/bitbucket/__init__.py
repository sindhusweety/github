from flask import Flask

def create_app():
    app = Flask(__name__)
    
    from . import ecdsa_app
    app.register_blueprint(ecdsa_app.ecdsa_app)
        
    return app
