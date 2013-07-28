import sys, os
from ConfigParser import SafeConfigParser

from sqlalchemy import create_engine
from sqlalchemy import Boolean, Column, DateTime, Enum, Integer, String, Text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base


cfg_file = SafeConfigParser()
path_to_cfg = os.path.abspath(os.path.dirname(sys.argv[0]))
path_to_cfg = os.path.join(path_to_cfg, 'automoderator.cfg')
cfg_file.read(path_to_cfg)

if cfg_file.get('database', 'system').lower() == 'sqlite':
    engine = create_engine(
        cfg_file.get('database', 'system')+':///'+\
        cfg_file.get('database', 'database'))
else:
    engine = create_engine(
        cfg_file.get('database', 'system')+'://'+\
        cfg_file.get('database', 'username')+':'+\
        cfg_file.get('database', 'password')+'@'+\
        cfg_file.get('database', 'host')+'/'+\
        cfg_file.get('database', 'database'))
Base = declarative_base()
Session = sessionmaker(bind=engine, expire_on_commit=False)
session = Session()


class Subreddit(Base):

    """Table containing the subreddits for the bot to monitor.

    name - The subreddit's name. "gaming", not "/r/gaming".
    enabled - Subreddit will not be checked if False
    conditions_yaml - YAML definition of the subreddit's conditions
    last_submission - The newest unfiltered submission the bot has seen
    last_spam - The newest filtered submission the bot has seen
    last_comment - The newest comment the bot has seen
    exclude_banned_modqueue - Should mirror the same setting's value on the
        subreddit. Used to determine if it's necessary to check whether
        submitters in the modqueue are shadowbanned or not.
    """

    __tablename__ = 'subreddits'

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False, unique=True)
    enabled = Column(Boolean, nullable=False, default=True)
    conditions_yaml = Column(Text)
    last_submission = Column(DateTime, nullable=False)
    last_spam = Column(DateTime, nullable=False)
    last_comment = Column(DateTime, nullable=False)
    exclude_banned_modqueue = Column(Boolean, nullable=False, default=False)


class StandardCondition(Base):

    """Table containing standard conditions that can be included by subreddits.

    name - A name identifying the condition (used to include that condition)
    yaml - The YAML definition of the standard condition
    """

    __tablename__ = 'standard_conditions'

    name = Column(String(255), primary_key=True)
    yaml = Column(Text)


class Log(Base):
    """Table containing a log of the bot's actions."""

    __tablename__ = 'log'

    id = Column(Integer, primary_key=True)
    item_fullname = Column(String(255), nullable=False)
    action = Column(Enum('approve',
                         'remove',
                         'report',
                         'link_flair',
                         'user_flair',
                         name='log_action'))
    condition_yaml = Column(Text)
    datetime = Column(DateTime)

