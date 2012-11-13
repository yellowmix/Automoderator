import sys, os
from ConfigParser import SafeConfigParser

from sqlalchemy import create_engine
from sqlalchemy import Integer, Enum, Float, String, Text, DateTime, Boolean, \
                       Column, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship, backref
from sqlalchemy.ext.declarative import declarative_base


cfg_file = SafeConfigParser()
path_to_cfg = os.path.abspath(os.path.dirname(sys.argv[0]))
path_to_cfg = os.path.join(path_to_cfg, 'modbot.cfg')
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
Session = sessionmaker(bind=engine)
session = Session()


class Subreddit(Base):

    """Table containing the subreddits for the bot to monitor.

    name - The subreddit's name. "gaming", not "/r/gaming".
    enabled - Subreddit will not be checked if False
    last_submission - The newest unfiltered submission the bot has seen
    last_spam - The newest filtered submission the bot has seen
    report_threshold - Any items with at least this many reports will trigger
        a mod-mail alert
    auto_reapprove - If True, bot will reapprove any reported submissions
        that were previously approved by a human mod - use with care
    check_all_conditions - If True, the bot will not stop and perform the
        action as soon as a single condition is matched, but will create
        a list of all matching conditions. This can be useful for subreddits
        with strict rules where a comment should include all reasons the post
        was removed.
    reported_comments_only - If True, will only check conditions against
        reported comments. If False, checks all comments in the subreddit.
        Extremely-active subreddits are probably best set to True.
    comment_header - Text prepended to all comments posted or messaged to
        users. Most useful if using check_all_conditions.
    comment_footer - Text appended to all comments posted or messaged to
        users. Most useful if using check_all_conditions.
    """

    __tablename__ = 'subreddits'

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False, unique=True)
    enabled = Column(Boolean, nullable=False, default=True)
    last_submission = Column(DateTime, nullable=False)
    last_spam = Column(DateTime, nullable=False)
    last_comment = Column(DateTime, nullable=False)
    auto_reapprove = Column(Boolean, nullable=False, default=False)
    check_all_conditions = Column(Boolean, nullable=False, default=False)
    reported_comments_only = Column(Boolean, nullable=False,
                                    default=False)
    comment_header = Column(Text)
    comment_footer = Column(Text)


class Condition(Base):

    """Table containing conditions, independent of subreddit.

    name - a name identifying a condition or set of conditions, allows
        subreddits to "subscribe" to standard conditions
    subject - The type of item to check
    attribute - Which attribute of the item to check
    value - A regex checked against the attribute. Automatically surrounded
        by ^ and $ when checked, so looks for "whole string" matches. To
        do a "contains" check, put .* on each end
    num_reports - The number of reports the item has. 0 and null are
        functionally equivalent. Note: to approve reported items, this
        must be set to at least 1
    auto_reapproving - Whether the num_reports condition should apply only
        during auto-reapproving, only before, or both (if null)
    is_gold - Whether the author has reddit gold or not
    is_shadowbanned - Whether the author is "shadowbanned" or not
    account_age - Account age condition (in days) for the item's author
    link_karma - Link karma condition for the item's author
    comment_karma - Comment karma condition for the item's author
    combined_karma - Combined karma condition for the item's author
    account_rank - Whether the author is an approved submitter ("contributor")
        or moderator in the subreddit - note that a moderator will also be
        considered to be a contributor
    inverse - If True, result of check will be reversed. Useful for
        "anything except" or "does not include"-type checks
    parent_id - The id of the condition this is a sub-condition of. If this
        is a top-level condition, will be null
    action - Which action to perform if this condition is matched
    spam - Whether to train the spam filter if this is a removal
    comment_method - What method the bot should use to deliver its comment
        when this condition is matched - reply to the item itself, send
        a PM to the item's author, or modmail to the subreddit
    comment - If set, bot will post this comment using the defined method
        when this condition is matched
    notes - not used by bot, space to keep notes on a condition

    """

    __tablename__ = 'conditions'

    id = Column(Integer, primary_key=True)
    name = Column(String(255))
    subject = Column(Enum('submission',
                          'comment',
                          'both',
                          name='condition_subject'),
                     nullable=False)
    attribute = Column(Enum('user',
                                  'title',
                                  'domain',
                                  'url',
                                  'body',
                                  'title+body',
                                  'url+body',
                                  'media_user',
                                  'media_title',
                                  'media_description',
                                  'author_flair_text',
                                  'author_flair_css_class',
                                  'meme_name',
                                  name='condition_attribute'),
                       nullable=False)
    value = Column(Text, nullable=False)
    num_reports = Column(Integer)
    auto_reapproving = Column(Boolean, default=False)
    is_gold = Column(Boolean)
    is_shadowbanned = Column(Boolean)
    account_age = Column(Integer)
    link_karma = Column(Integer)
    comment_karma = Column(Integer)
    combined_karma = Column(Integer)
    account_rank = Column(Enum('contributor',
                               'moderator',
                               name='rank'))
    inverse = Column(Boolean, nullable=False, default=False)
    parent_id = Column(Integer, ForeignKey('conditions.id'))
    action = Column(Enum('approve',
                         'remove',
                         'alert',
                         'set_flair',
                         'report',
                         name='action'))
    spam = Column(Boolean)
    set_flair_text = Column(Text)
    set_flair_class = Column(String(255))
    comment_method = Column(Enum('comment',
                                 'message',
                                 'modmail',
                                 name='comment_method'))
    comment = Column(Text)
    notes = Column(Text)

    additional_conditions = relationship('Condition',
        lazy='joined', join_depth=1)

    check_shadowbanned = False


class SubredditCondition(Base):

    """Table assigning conditions to particular subreddits.

    override_default_action - whether to use the action, comment_method,
        comment, set_flair_text, and set_flair_class from this table
        or the standard ones defined in the condition

    """

    __tablename__ = 'subreddit_conditions'

    subreddit_id = Column(Integer,
                          ForeignKey('subreddits.id'),
                          primary_key=True,
                          nullable=False)
    condition_id = Column(Integer,
                          ForeignKey('conditions.id'),
                          primary_key=True,
                          nullable=False)
    override_default_action = Column(Boolean,
                                     nullable=False,
                                     default=False)
    action = Column(Enum('approve',
                         'remove',
                         'alert',
                         'set_flair',
                         'report',
                         name='action'))
    spam = Column(Boolean)
    set_flair_text = Column(Text)
    set_flair_class = Column(String(255))
    comment_method = Column(Enum('comment',
                                 'message',
                                 'modmail',
                                 name='comment_method'))
    comment = Column(Text)

    subreddit = relationship('Subreddit',
        backref=backref('conditions', lazy='dynamic'))

    condition = relationship('Condition',
        backref=backref('subreddits', lazy='dynamic'))

    # if override_default_action is not set, we will pass through any
    # action-related attributes to the underlying Condition object
    def __getattribute__(self, attr):
        overlayable_attrs = ['action', 'spam', 'comment_method', 'comment',
                             'set_flair_text', 'set_flair_class']
        if attr not in overlayable_attrs:
            return object.__getattribute__(self, attr)

        if (not self.override_default_action and
                 attr in overlayable_attrs):
            return getattr(self.condition, attr)

        return object.__getattribute__(self, attr)

    # pass any nonexistent attrs through to the Condition
    def __getattr__(self, attr):
        return getattr(self.condition, attr)


class ActionLog(Base):
    """Table containing a log of the bot's actions."""
    __tablename__ = 'action_log'

    id = Column(Integer, primary_key=True)
    subreddit_id = Column(Integer,
                             ForeignKey('subreddits.id'),
                             nullable=False)
    title = Column(Text)
    user = Column(String(255))
    url = Column(Text)
    domain = Column(String(255))
    permalink = Column(String(255))
    created_utc = Column(DateTime)
    action_time = Column(DateTime)
    action = Column(Enum('approve',
                         'remove',
                         'alert',
                         'set_flair',
                         'report',
                         name='action'))
    matched_condition = Column(Integer, ForeignKey('conditions.id'))

    subreddit = relationship('Subreddit',
        backref=backref('actions', lazy='dynamic'))

    condition = relationship('Condition',
        backref=backref('actions', lazy='dynamic'))


class AutoReapproval(Base):
    """Table keeping track of posts that have been auto-reapproved."""
    __tablename__ = 'auto_reapprovals'

    id = Column(Integer, primary_key=True)
    subreddit_id = Column(Integer,
                          ForeignKey('subreddits.id'),
                          nullable=False)
    permalink = Column(String(255))
    original_approver = Column(String(255))
    total_reports = Column(Integer, nullable=False, default=0)
    first_approval_time = Column(DateTime)
    last_approval_time = Column(DateTime)

    subreddit = relationship('Subreddit',
        backref=backref('auto_reapprovals', lazy='dynamic'))


class UserCache(Base):
    """Cached user data."""
    __tablename__ = 'user_cache'

    user = Column(String(255), nullable=False, primary_key=True)
    is_gold = Column(Boolean)
    is_shadowbanned = Column(Boolean)
    created_utc = Column(DateTime)
    link_karma = Column(Integer)
    comment_karma = Column(Integer)
    shadowbanned_last_check = Column(DateTime)
    info_last_check = Column(DateTime)

