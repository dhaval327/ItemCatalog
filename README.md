#Item Catalog

  This project is a data-driven full-stack web application created using Python, Flask, HTML, and the SQLAlchemy module. The project allows users to create an item to place within a category that exists in the catalog. These items can be viewed easily within a web browser. More CRUD operations are permitted based on whether the user is logged in to the application and whether or not they are the creators of that item.

  Included Files:
    catalog_app.py
    database_setup.py
    populate_db.py
    client_secrets.json
    static folder with CSS stylings
    templates folder with HTML for pages

##Installation and Dependencies

To run this code, you will need to install the following:
  Python: https://www.python.org
  Flask: Can be installed with "pip install flask" on command line
  SQLAlchemy: Can be installed with "pip install SQLAlchemy" on command line
  OAuth2Client: Can be installed with "pip install oauth2client" on command line
  HTTPLib2: Can be installed with "pip install httplib2" on command line

If using a windows computer and you need a unix-like terminal program:
  Git Bash: https://gitforwindows.org
  
##Execution

Steps to run the program:
  1. Within the command line (terminal for mac or git bash for windows), switch directories to the project directory.
  2. Run database set up code by entering "python database_setup.py" within the command line.
  3. The following step is optional: populate database with temporary information by entering "python populate_db.py" within the command line.
  4. Start the server by entering "python catalog_app.py" within the command line.
  5. Access the app through a web browser by visiting http://localhost:8001/


