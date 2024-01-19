#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource

from config import app, db, api, bcrypt
from models import User

class ClearSession(Resource):

    def delete(self):
    
        session['page_views'] = None
        session['user_id'] = None

        return {}, 204

class Signup(Resource):
    
    def post(self):
        json = request.get_json()
        user = User(
            username=json['username'],
            password_hash=json['password']
        )
        db.session.add(user)
        db.session.commit()
        
        session['user_id'] = user.id
        session['username'] = user.username
        
        return user.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        if 'user_id' in session and session['user_id']:
            user = User.query.filter(User.id == session['user_id']).first()
            
            return user.to_dict(),200
        else:
            return {},204

class Login(Resource):
    def post(self):
        json = request.get_json()
        
        user = User.query.filter(User.username == json['username']).first()
        
        if not user:
            return {"error":"User not found"},404
        
        if bcrypt.check_password_hash(user._password_hash, json['password']):
            if 'user_id' not in session and not session['user_id']:
                session['user_id'] = user.id
                session['username'] = username
            
            return user.to_dict(), 200
        else:
            return {"error":"Invalid credentials"},401
        
        

class Logout(Resource):
    def delete(self):
        session['user_id'] = ""
        
        return {},204

api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
