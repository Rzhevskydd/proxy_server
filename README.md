# Ржевский Даниил : proxy_server

### Start mannually
```
git clone git@github.com:Rzhevskydd/proxy_server.git
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sh gen.sh
python -m proxy
```


### Docker build
```
git clone git@github.com:Rzhevskydd/proxy_server.git
docker build -t proxy .
docker run -p 7888:7888 proxy
```
