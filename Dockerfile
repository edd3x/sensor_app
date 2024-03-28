# To enable ssh & remote debugging on app service change the base image to the one below
FROM mcr.microsoft.com/azure-functions/python:4-python3.10

# Update and install required python packages
RUN pip install --upgrade pip

COPY requirements.txt /
RUN pip install -r /requirements.txt


# Copy files to images
COPY . /home/site/wwwroot

# Set working directory
WORKDIR /home/site/wwwroot

ENV SOLARA_APP=app.py

# Export web server port
EXPOSE 8765

# By default run the start up command
CMD ["solara" ,"run", "app.py", "--host=0.0.0.0"]
# CMD ["gunicorn" ,"-w", "4", "--threads=20","-b","0.0.0.0:8765", "solara.server.flask:app"]
# CMD ["SOLARA_APP=sol.py", "uvicorn", "--workers", "4" "--host", "0.0.0.0", "--port", "8765", "solara.server.starlette:app"]