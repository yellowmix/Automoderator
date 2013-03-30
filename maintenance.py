"""Run occasionally via cron for maintenance tasks."""

from datetime import datetime, timedelta
import praw
from models import cfg_file, Log, session, Subreddit


def main():
    r = praw.Reddit(user_agent=cfg_file.get('reddit', 'user_agent'))
    r.login(cfg_file.get('reddit', 'username'),
            cfg_file.get('reddit', 'password'))

    # update exclude_banned_modqueue values for subreddits
    subreddits = (session.query(Subreddit)
                         .filter(Subreddit.enabled == True)
                         .all())
    for sr in subreddits:
        try:
            settings = r.get_subreddit(sr.name).get_settings()
            sr.exclude_banned_modqueue = settings['exclude_banned_modqueue']
        except Exception as e:
            sr.exclude_banned_modqueue = False

    session.commit()

    # delete old log entries
    log_retention_days = int(cfg_file.get('database', 'log_retention_days'))
    log_cutoff = datetime.utcnow() - timedelta(days=log_retention_days)
    deleted = session.query(Log).filter(Log.datetime < log_cutoff).delete()
    session.commit()
    print 'Deleted {0} log rows'.format(deleted)


if __name__ == '__main__':
    main()
