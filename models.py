import sys, os
from ConfigParser import SafeConfigParser

from modbot_site import app
from flaskext.sqlalchemy import SQLAlchemy


cfg_file = SafeConfigParser()
path_to_cfg = os.path.abspath(os.path.dirname(sys.argv[0]))
path_to_cfg = os.path.join(path_to_cfg, 'modbot.cfg')
cfg_file.read(path_to_cfg)

app.config['SQLALCHEMY_DATABASE_URI'] = \
    cfg_file.get('database', 'system')+'://'+\
    cfg_file.get('database', 'username')+':'+\
    cfg_file.get('database', 'password')+'@'+\
    cfg_file.get('database', 'host')+'/'+\
    cfg_file.get('database', 'database')
db = SQLAlchemy(app)


class Subreddit(db.Model):

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

    """

    __tablename__ = 'subreddits'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    last_submission = db.Column(db.DateTime, nullable=False)
    last_spam = db.Column(db.DateTime, nullable=False)
    last_comment = db.Column(db.DateTime, nullable=False)
    auto_reapprove = db.Column(db.Boolean, nullable=False, default=False)
    check_all_conditions = db.Column(db.Boolean, nullable=False, default=False)
    reported_comments_only = db.Column(db.Boolean, nullable=False,
                                       default=False)


class Condition(db.Model):

    """Table containing the conditions for each subreddit.

    subject - The type of item to check
    attribute - Which attribute of the item to check
    value - A regex checked against the attribute. Automatically surrounded
        by ^ and $ when checked, so looks for "whole string" matches. To
        do a "contains" check, put .* on each end
    num_reports - The number of reports the item has. Note that setting to
        None means a matching item *must* have 0 reports.
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

    id = db.Column(db.Integer, primary_key=True)
    subreddit_id = db.Column(db.Integer, db.ForeignKey('subreddits.id'))
    subject = db.Column(db.Enum('submission',
                                'comment',
                                'both',
                                name='condition_subject'),
                        nullable=False)
    attribute = db.Column(db.Enum('user',
                                  'title',
                                  'domain',
                                  'url',
                                  'body',
                                  'media_user',
                                  'media_title',
                                  'media_description',
                                  'author_flair_text',
                                  'author_flair_css_class',
                                  'meme_name',
                                  name='condition_attribute'),
                          nullable=False)
    value = db.Column(db.Text, nullable=False)
    num_reports = db.Column(db.Integer)
    auto_reapproving = db.Column(db.Boolean, default=False)
    is_gold = db.Column(db.Boolean)
    is_shadowbanned = db.Column(db.Boolean)
    account_age = db.Column(db.Integer)
    link_karma = db.Column(db.Integer)
    comment_karma = db.Column(db.Integer)
    combined_karma = db.Column(db.Integer)
    account_rank = db.Column(db.Enum('contributor',
                                     'moderator',
                                     name='rank'))
    inverse = db.Column(db.Boolean, nullable=False, default=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('conditions.id'))
    action = db.Column(db.Enum('approve',
                               'remove',
                               'alert',
                               'set_flair',
                               name='action'))
    spam = db.Column(db.Boolean)
    set_flair_text = db.Column(db.Text)
    set_flair_class = db.Column(db.String(255))
    comment_method = db.Column(db.Enum('comment',
                                       'message',
                                       'modmail',
                                       name='comment_method'))
    comment = db.Column(db.Text)
    notes = db.Column(db.Text)

    subreddit = db.relationship('Subreddit',
        backref=db.backref('conditions', lazy='dynamic'))

    additional_conditions = db.relationship('Condition',
        lazy='joined', join_depth=1)


class ActionLog(db.Model):
    """Table containing a log of the bot's actions."""
    __tablename__ = 'action_log'

    id = db.Column(db.Integer, primary_key=True)
    subreddit_id = db.Column(db.Integer,
                             db.ForeignKey('subreddits.id'),
                             nullable=False)
    title = db.Column(db.Text)
    user = db.Column(db.String(255))
    url = db.Column(db.Text)
    domain = db.Column(db.String(255))
    permalink = db.Column(db.String(255))
    created_utc = db.Column(db.DateTime)
    action_time = db.Column(db.DateTime)
    action = db.Column(db.Enum('approve',
                               'remove',
                               'alert',
                               'set_flair',
                               name='action'))
    matched_condition = db.Column(db.Integer, db.ForeignKey('conditions.id'))

    subreddit = db.relationship('Subreddit',
        backref=db.backref('actions', lazy='dynamic'))

    condition = db.relationship('Condition',
        backref=db.backref('actions', lazy='dynamic'))


class AutoReapproval(db.Model):
    """Table keeping track of posts that have been auto-reapproved."""
    __tablename__ = 'auto_reapprovals'

    id = db.Column(db.Integer, primary_key=True)
    subreddit_id = db.Column(db.Integer,
                             db.ForeignKey('subreddits.id'),
                             nullable=False)
    permalink = db.Column(db.String(255))
    original_approver = db.Column(db.String(255))
    total_reports = db.Column(db.Integer, nullable=False, default=0)
    first_approval_time = db.Column(db.DateTime)
    last_approval_time = db.Column(db.DateTime)

    subreddit = db.relationship('Subreddit',
        backref=db.backref('auto_reapprovals', lazy='dynamic'))

