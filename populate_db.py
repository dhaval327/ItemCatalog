#!/usr/bin/env python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, User, Category, Item

engine = create_engine('sqlite:///item_catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create dummy user
user1 = User(name="Jimmy", email="JimmyJim@gmail.com", picture='none.png')
session.add(user1)
session.commit()

category1 = Category(name='Sports')
session.add(category1)
session.commit()

item1 = Item(name='Baseball Glove', description='This is a baseball glove', price='$4.99', category=category1,
             user=user1)
session.add(item1)
session.commit()

print('Added to database!')
