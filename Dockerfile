FROM python:3.6

WORKDIR /cryptographyApp

COPY . .

RUN python -m pip install --upgrade pip

RUN pip install -r requirements.txt

CMD [ "python", "cryptographyApp.py" ]