"""API smoke tests; real Gemini responses require a configured API key."""
import importlib
import os
from fastapi.testclient import TestClient


def test_registration_chat_documents_and_isolation(tmp_path, monkeypatch):
    monkeypatch.setenv('DATABASE_PATH', str(tmp_path/'test.db'))
    monkeypatch.setenv('APP_ENV', 'development')
    import server
    importlib.reload(server)
    with TestClient(server.app) as client:
        assert client.get('/healthz').json()['status'] == 'ok'
        assert client.get('/api/me').status_code == 401
        assert client.post('/api/register',json={'email':'a@example.com','password':'password123'}).status_code == 200
        assert client.get('/api/me').json()['email'] == 'a@example.com'
        c=client.post('/api/chats',json={'mode':'study'})
        assert c.status_code == 200
        cid=c.json()['id']
        assert client.get('/api/chats/'+cid).status_code == 200
        doc=client.post('/api/documents',files={'file':('notes.txt',b'Physics is the study of matter.','text/plain')})
        assert doc.status_code == 200
        assert client.get('/api/documents').json()[0]['name']=='notes.txt'
        goal=client.post('/api/goals',json={'title':'Revise networks'})
        assert goal.status_code == 200
        assert client.patch('/api/goals/'+goal.json()['id'],json={'done':True}).status_code == 200
        assert client.get('/api/goals').json()[0]['done']==1
        assert client.post('/api/chats/'+cid+'/stream',json={'message':'Hello'}).status_code == 503
        assert client.post('/api/logout').status_code == 200
        assert client.get('/api/me').status_code == 401
        assert client.post('/api/register',json={'email':'b@example.com','password':'password123'}).status_code == 200
        assert client.get('/api/chats/'+cid).status_code == 404
        assert client.get('/api/documents').json()==[]
        assert client.get('/api/goals').json()==[]


def test_cross_origin_rejected(tmp_path,monkeypatch):
    monkeypatch.setenv('DATABASE_PATH', str(tmp_path/'another.db'))
    monkeypatch.setenv('APP_ENV', 'development')
    import server
    importlib.reload(server)
    with TestClient(server.app) as c:
        r=c.post('/api/register',headers={'Origin':'https://other.example'},json={'email':'c@example.com','password':'password123'})
        assert r.status_code==403
