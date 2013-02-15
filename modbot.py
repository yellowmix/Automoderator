import re
import logging, logging.config
import urllib2
from calendar import timegm
from datetime import datetime, timedelta
from time import time

import praw
from bs4 import BeautifulSoup
from sqlalchemy import func
from sqlalchemy.sql import and_
from sqlalchemy.orm.exc import NoResultFound

from models import cfg_file, path_to_cfg, session, Subreddit, Condition, \
                   SubredditCondition, ActionLog, AutoReapproval, UserCache

# global reddit session
r = None
# which queues to check and the function to call
QUEUES = {'report': 'get_reports',
          'spam': 'get_mod_queue',
          'submission': 'get_new_by_date',
          'comment': 'get_comments'}


def log_request(req_type, num_reqs=1):
    """Logs a reddit request."""
    if not hasattr(log_request, 'counts'):
        log_request.counts = dict()

    if req_type in log_request.counts:
        log_request.counts[req_type] += num_reqs
    else:
        log_request.counts[req_type] = num_reqs

def perform_action(subreddit, item, condition, matchobj):
    """Performs the action for the condition(s).
    
    Also delivers the comment (if set) and creates an ActionLog entry.
    """
    
    global r
    disclaimer = ('\n\n*[I am a bot](http://www.reddit.com/r/AutoModerator/'
                    'comments/q11pu/what_is_automoderator/), and this action '
                    'was performed automatically. Please [contact the '
                    'moderators of this subreddit](http://www.reddit.com/'
                    'message/compose?to=%2Fr%2F'+item.subreddit.display_name+
                    ') if you have any questions or concerns.*')

    # build the comment if multiple conditions were matched
    if isinstance(condition, list):
        comment = ''
        if any([c.comment for c in condition]):
            for c in condition:
                if c.comment:
                    comment += '* '+c.comment+'\n'

        # bit of a hack and only logs and uses attributes from first
        # condition matched, should find a better method
        condition = condition[0]
        match = matchobj[0]
    else:
        comment = condition.comment
        match = matchobj

    # abort if it's an alert/report/removal/set_flair that's already triggered
    if condition.action in ['alert', 'report', 'remove', 'set_flair']:
        try:
            session.query(ActionLog).filter(
                and_(ActionLog.permalink == get_permalink(item),
                     ActionLog.matched_condition == condition.id)).one()
            return
        except NoResultFound:
            pass

    # perform replacements with match groups
    comment = replace_placeholders(comment, match)
    flair_text = replace_placeholders(condition.set_flair_text, match)
    flair_class = replace_placeholders(condition.set_flair_class, match)

    # perform the action
    if condition.action == 'remove':
        item.remove(condition.spam)
    elif condition.action == 'approve':
        item.approve()
    elif condition.action == 'set_flair':
        item.set_flair(flair_text, flair_class)
    elif condition.action == 'report':
        item.report()

    log_request(condition.action)

    if comment:
        # put together the comment parts for "public" comments
        if condition.comment_method in ['comment', 'message']:
            if subreddit.comment_header:
                comment = subreddit.comment_header+'\n\n'+comment
            if subreddit.comment_footer:
                comment = comment+'\n\n'+subreddit.comment_footer
            comment += disclaimer

        # deliver the comment
        if condition.comment_method == 'comment':
            post_comment(item, comment)
            log_request('comment')
            log_request('distinguish')
        elif condition.comment_method == 'modmail':
            r.send_message('/r/'+subreddit.name,
                          'AutoModerator condition matched',
                          get_permalink(item)+'\n\n'+comment)
            log_request('modmail')
        elif condition.comment_method == 'message':
            if item.author:
                r.send_message(item.author.name,
                              'AutoModerator condition matched',
                              get_permalink(item)+'\n\n'+comment)
                log_request('message')

    # log the action taken
    action_log = ActionLog()
    action_log.subreddit_id = subreddit.id
    if item.author:
        action_log.user = item.author.name
    action_log.permalink = get_permalink(item)
    action_log.created_utc = datetime.utcfromtimestamp(item.created_utc)
    action_log.action_time = datetime.utcnow()
    action_log.action = condition.action
    action_log.matched_condition = condition.id

    if isinstance(item, praw.objects.Submission):
        action_log.title = item.title
        action_log.url = item.url
        action_log.domain = item.domain
        logging.info('  /r/%s: %s submission "%s"',
                        subreddit.name,
                        condition.action,
                        item.title.encode('ascii', 'ignore'))
    elif isinstance(item, praw.objects.Comment):
        if item.author:
            logging.info('  /r/%s: %s comment by user %s',
                            subreddit.name,
                            condition.action,
                            item.author.name)
        else:
            logging.info('  /r/%s: %s comment by deleted user',
                            subreddit.name,
                            condition.action)

    session.add(action_log)
    session.commit()


def replace_placeholders(string, match):
    """Replace placeholders in string with corresponding groups from match."""
    if string and not isinstance(match, bool):
        return match.expand(string)
    else:
        return string


def post_comment(item, comment):
    """Posts a distinguished comment as a reply to an item."""
    if isinstance(item, praw.objects.Submission):
        response = item.add_comment(comment)
        response.distinguish()
    elif isinstance(item, praw.objects.Comment):
        response = item.reply(comment)
        response.distinguish()


def check_items(name, items, sr_dict, cond_dict, stop_time):
    """Checks the items generator for any matching conditions."""
    item_count = 0
    start_time = time()
    seen_subs = set()

    logging.info('Checking new %ss', name)

    try:
        for item in items:
            # skip any items in /new that have been approved
            if name == 'submission' and item.approved_by:
                continue

            item_time = datetime.utcfromtimestamp(item.created_utc)
            if item_time <= stop_time:
                break

            subreddit = sr_dict[item.subreddit.display_name.lower()]
            conditions = cond_dict[item.subreddit.display_name.lower()][name]

            # don't need to check for shadowbanned unless we're in spam
            if name == 'spam':
                for condition in conditions:
                    condition.check_shadowbanned = True
            else:
                for condition in conditions:
                    condition.check_shadowbanned = False

            item_count += 1

            if subreddit.name not in seen_subs:
                setattr(subreddit, 'last_'+name, item_time)
                seen_subs.add(subreddit.name)

            logging.debug('  Checking item %s', get_permalink(item))

            # check removal conditions, stop checking if any matched
            if check_conditions(subreddit, item,
                    [c for c in conditions if c.action == 'remove']):
                continue

            # check set_flair conditions 
            check_conditions(subreddit, item,
                    [c for c in conditions if c.action == 'set_flair'])

            # check approval conditions
            check_conditions(subreddit, item,
                    [c for c in conditions if c.action == 'approve'])

            # check alert conditions
            check_conditions(subreddit, item,
                    [c for c in conditions if c.action == 'alert'])

            # check report conditions
            check_conditions(subreddit, item,
                    [c for c in conditions if c.action == 'report'])

            # if doing reports, check auto-reapproval if enabled
            if (name == 'report' and subreddit.auto_reapprove and
                    item.approved_by is not None):
                try:
                    # see if this item has already been auto-reapproved
                    entry = (session.query(AutoReapproval).filter(
                            AutoReapproval.permalink == get_permalink(item))
                            .one())
                    in_db = True
                except NoResultFound:
                    entry = AutoReapproval()
                    entry.subreddit_id = subreddit.id
                    entry.permalink = get_permalink(item)
                    entry.original_approver = item.approved_by.name
                    entry.total_reports = 0
                    entry.first_approval_time = datetime.utcnow()
                    in_db = False

                if (in_db or item.approved_by.name !=
                        cfg_file.get('reddit', 'username')):
                    item.approve()
                    entry.total_reports += item.num_reports
                    entry.last_approval_time = datetime.utcnow()

                    session.add(entry)
                    session.commit()
                    logging.info('  Re-approved %s', entry.permalink)
                    log_request('reapprove')
                            
        session.commit()
    except Exception as e:
        logging.error('  ERROR: %s', e)
        session.rollback()

    logging.info('  Checked %s items in %s',
            item_count, elapsed_since(start_time))
    log_request('listing', item_count / 100 + 1)


def filter_conditions(name, conditions):
    """Filters a list of conditions based on the queue's needs."""
    if name == 'spam':
        return [c for c in conditions if c.num_reports < 1]
    elif name == 'report':
        return [c for c in conditions if
                c.action != 'report' and
                (c.action != 'approve' or c.num_reports > 0) and
                c.is_shadowbanned != True]
    elif name == 'submission':
        return [c for c in conditions if c.action != 'approve' and
                c.is_shadowbanned != True]
    elif name == 'comment':
        return [c for c in conditions if c.action != 'approve' and
                c.is_shadowbanned != True]


def check_conditions(subreddit, item, conditions):
    """Checks an item against a set of conditions.

    Returns the first condition that matches, or a list of all conditions that
    match if check_all_conditions is set on the subreddit. Returns None if no
    conditions match.
    """
    if isinstance(item, praw.objects.Submission):
        conditions = [c for c in conditions
                          if c.subject == 'submission' or
                             c.subject == 'both']
    elif isinstance(item, praw.objects.Comment):
        conditions = [c for c in conditions
                          if c.subject == 'comment' or
                             c.subject == 'both']

    # sort the conditions so the easiest ones are checked first
    conditions.sort(key=condition_complexity)
    matched = list()
    match_objs = list()

    for condition in conditions:
        try:
            match = check_condition(item, condition)
        except Exception as e:
            logging.error('  ERROR: Condition #%s - %s', condition.id, e)
            match = None

        if match:
            if subreddit.check_all_conditions:
                matched.append(condition)
                match_objs.append(match)
            else:
                perform_action(subreddit, item, condition, match)
                return condition

    if subreddit.check_all_conditions and len(matched) > 0:
        perform_action(subreddit, item, matched, match_objs)
        return matched
    return None


def check_condition(item, condition):
    """Checks an item against a single condition (and sub-conditions).
    
    Returns the MatchObject from the re if condition satisfied, or returns
    None if not.
    """
    start_time = time()
    test_string = None

    if condition.attribute == 'user':
        if item.author:
            test_string = item.author.name
    elif (condition.attribute == 'body' and
            isinstance(item, praw.objects.Submission)):
        test_string = item.selftext
    elif condition.attribute.startswith('media_'):
        if item.media:
            try:
                if condition.attribute == 'media_user':
                    test_string = item.media['oembed']['author_name']
                elif condition.attribute == 'media_title':
                    test_string = item.media['oembed']['title']
                elif condition.attribute == 'media_description':
                    test_string = item.media['oembed']['description']
            except KeyError:
                test_string = ''
        else:
            test_string = ''
    elif condition.attribute == 'meme_name':
        test_string = get_meme_name(item)
    elif condition.attribute == 'title+body':
        if isinstance(item, praw.objects.Submission):
            test_string = [item.title, item.selftext]
        else:
            test_string = item.body
    elif condition.attribute == 'url+body':
        if isinstance(item, praw.objects.Submission):
            test_string = [item.url, item.selftext]
        else:
            test_string = item.body
    else:
        test_string = getattr(item, condition.attribute)
    if not test_string:
        test_string = ''

    if isinstance(test_string, list):
        for test in test_string:
            match = re.search('^'+condition.value+'$',
                        test.lower(),
                        re.DOTALL|re.UNICODE|re.IGNORECASE)
            if match:
                break
    else:
        match = re.search('^'+condition.value+'$',
                    test_string.lower(),
                    re.DOTALL|re.UNICODE|re.IGNORECASE)

    if match:
        satisfied = True
    else:
        satisfied = False

    # flip the result it's an inverse condition
    if condition.inverse:
        satisfied = not satisfied

    # check number of reports if necessary
    if satisfied and condition.num_reports is not None:
        if condition.auto_reapproving != False:
            # get number of reports already cleared
            try:
                entry = (session.query(AutoReapproval).filter(
                         AutoReapproval.permalink == get_permalink(item))
                        .one())
                previous_reports = entry.total_reports
            except NoResultFound:
                previous_reports = 0
            total_reports = item.num_reports + previous_reports
        else:
            total_reports = item.num_reports

        satisfied = (total_reports >= condition.num_reports)

    # check whether it's a reply or top-level comment if necessary
    if (satisfied and
            isinstance(item, praw.objects.Comment) and
            condition.is_reply is not None and
            condition.is_reply != item.parent_id.startswith('t1_')):
        satisfied = False

    # check user conditions if necessary
    if satisfied:
        satisfied = check_user_conditions(item, condition)

    # make sure all sub-conditions are satisfied as well
    if satisfied:
        for sub_condition in condition.additional_conditions:
            sub_match = check_condition(item, sub_condition)
            if not sub_match:
                satisfied = False
                break

    logging.debug('    Condition #%s, result %s in %s',
                    condition.id, satisfied, elapsed_since(start_time))
    if satisfied:
        if not condition.inverse:
            return match
        else:
            return True
    else:
        return None


def check_user_conditions(item, condition):
    """Checks an item's author against the age/karma/has-gold requirements."""
    # if no user conditions are set, no need to check at all
    if (condition.is_gold is None and
            condition.is_shadowbanned is None and
            condition.link_karma is None and
            condition.comment_karma is None and
            condition.combined_karma is None and
            condition.account_age is None and
            condition.account_rank is None):
        return True

    # returning True will result in the action being performed
    # so when removing or alerting, return True if they DON'T meet user reqs
    # but for approving and flair we return True if they DO meet it
    if condition.action in ['remove', 'alert', 'report']:
        fail_result = True
    elif condition.action in ['approve', 'set_flair']:
        fail_result = False

    # if they deleted the post, fail user checks
    if not item.author:
        return fail_result

    # user rank check
    if condition.account_rank is not None:
        if not user_has_rank(item.subreddit, item.author,
                            condition.account_rank):
            return fail_result

    # shadowbanned check
    if condition.is_shadowbanned is not None and condition.check_shadowbanned:
        # this probably isn't correct, but it's how it worked before
        if user_is_shadowbanned(item.author.name):
            return fail_result

    # get user info
    user = get_user_info(item.author.name, condition)
    if user is None:
        return fail_result

    # reddit gold check
    if condition.is_gold is not None:
        if condition.is_gold != user.is_gold:
            return fail_result

    # karma checks
    if condition.link_karma is not None:
        if user.link_karma < condition.link_karma:
            return fail_result
    if condition.comment_karma is not None:
        if user.comment_karma < condition.comment_karma:
            return fail_result
    if condition.combined_karma is not None:
        if (user.link_karma + user.comment_karma) \
                < condition.combined_karma:
            return fail_result

    # account age check
    if condition.account_age is not None:
        if (datetime.utcnow() \
                - datetime.utcfromtimestamp(user.created_utc)).days \
                < condition.account_age:
            return fail_result

    # user passed all checks
    return not fail_result


def user_has_rank(subreddit, user, rank):
    """Returns true if user has sufficient rank in the subreddit."""
    sr_name = subreddit.display_name.lower()

    # fetch mod/contrib lists if necessary
    if sr_name not in user_has_rank.moderator_cache:
        mod_list = set()
        for mod in subreddit.get_moderators():
            mod_list.add(mod.name)
        user_has_rank.moderator_cache[sr_name] = mod_list
        log_request('moderator_list')

        contrib_list = set()
        for contrib in subreddit.get_contributors():
            contrib_list.add(contrib.name)
        user_has_rank.contributor_cache[sr_name] = contrib_list
        log_request('contributor_list')

    if user.name in user_has_rank.moderator_cache[sr_name]:
        if rank == 'moderator' or rank == 'contributor':
            return True
    elif user.name in user_has_rank.contributor_cache[sr_name]:
        if rank == 'contributor':
            return True
    return False
user_has_rank.moderator_cache = dict()
user_has_rank.contributor_cache = dict()


def user_is_shadowbanned(username):
    """Returns true if the user is shadowbanned."""
    global r

    # build user cache by parsing modqueue html if this is first call
    if not user_is_shadowbanned.user_cache:
        # would be better as a minimal multireddit
        page = r._request('http://www.reddit.com/r/mod/about/modqueue')
        log_request('modqueue_html')
        soup = BeautifulSoup(page)
        results = soup.find_all(class_='spam')

        for item in results:
            user = item.find(class_='entry').find(class_='author').text
            if 'banned-user' in item.attrs['class']:
                user_is_shadowbanned.user_cache[user] = True
            else:
                user_is_shadowbanned.user_cache[user] = False

    # if this is one of the users we scraped, return that result
    if username in user_is_shadowbanned.user_cache:
        return user_is_shadowbanned.user_cache[username]

    # fall back to trying to load the user's overview
    user = r.get_redditor(username, fetch=False)
    log_request('user')
    try: # try to get user overview
        list(user.get_overview(limit=1))
    except: # if that failed, they're probably shadowbanned
        return True
    return False
user_is_shadowbanned.user_cache = dict()


def get_user_info(username, condition):
    """Gets user info from cache, or from reddit if not cached or expired."""
    global r

    try:
        cache_row = (session.query(UserCache)
                        .filter(UserCache.user == username)
                        .one())
        # see if the condition includes a check that expires
        if (condition.is_gold or
                condition.link_karma or
                condition.comment_karma or
                condition.combined_karma):
            expiry = timedelta(days=1)
        else:
            expiry = None

        # if not past the expiry, return cached data
        if (not expiry or
                datetime.utcnow() - cache_row.info_last_check < expiry):
            cached = r.get_redditor(username, fetch=False)
            cached.is_gold = cache_row.is_gold
            cached.created_utc = timegm(cache_row.created_utc.timetuple())
            cached.link_karma = cache_row.link_karma
            cached.comment_karma = cache_row.comment_karma
            
            return cached
    except NoResultFound:
        cache_row = UserCache()
        cache_row.user = username
        session.add(cache_row)

    # fetch the user's info from reddit
    try:
        user = r.get_redditor(username)
        log_request('user')

        # save to cache
        cache_row.is_gold = user.is_gold
        cache_row.created_utc = datetime.utcfromtimestamp(user.created_utc)
        cache_row.link_karma = user.link_karma
        cache_row.comment_karma = user.comment_karma
        cache_row.info_last_check = datetime.utcnow()
        session.commit()
    except urllib2.HTTPError as e:
        if e.code == 404:
            # weird case where the user is deleted but API still shows username
            return None
        else:
            raise

    return user


def get_permalink(item):
    """Returns the permalink for the item."""
    if isinstance(item, praw.objects.Submission):
        return item.permalink
    elif isinstance(item, praw.objects.Comment):
        return ('http://www.reddit.com/r/'+
                item.subreddit.display_name+
                '/comments/'+item.link_id.split('_')[1]+
                '/a/'+item.id)


def respond_to_modmail(modmail, start_time):
    """Responds to modmail if any submitters sent one before approval."""
    cache = list()
    # respond to any modmail sent in the last 5 mins
    time_window = timedelta(minutes=5)
    approvals = session.query(ActionLog).filter(
                    and_(ActionLog.action == 'approve',
                         ActionLog.action_time >= start_time - time_window)
                    ).all()

    for item in approvals:
        found = None
        done = False

        for i in cache:
            if datetime.utcfromtimestamp(i.created_utc) < item.created_utc:
                done = True
                log_request('modmail_listing', len(cache) / 100 + 1)
                break
            if (i.dest.lower() == '#'+item.subreddit.name.lower() and
                    i.author.name == item.user and
                    not i.replies):
                found = i
                break

        if not found and not done:
            for i in modmail:
                cache.append(i)
                if datetime.utcfromtimestamp(i.created_utc) < item.created_utc:
                    break
                if (i.dest.lower() == '#'+item.subreddit.name.lower() and
                        i.author.name == item.user and
                        not i.replies):
                    found = i
                    break

        if found:
            found.reply('Your submission has been approved automatically by '+
                cfg_file.get('reddit', 'username')+'. For future submissions '
                'please wait at least 5 minutes before messaging the mods, '
                'this post would have been approved automatically even '
                'without you sending this message.')
            log_request('modmail')


def get_meme_name(item):
    """Gets the item's meme name, if relevant/possible."""
    # determine the URL of the page that will contain the meme name
    if item.domain in ['quickmeme.com', 'qkme.me']:
        url = item.url
    elif item.domain.endswith('.qkme.me'):
        matches = re.search('.+/(.+?)\.jpg$', item.url)
        url = 'http://qkme.me/'+matches.group(1)
    elif item.domain.endswith('memegenerator.net'):
        for regex in ['/instance/(\\d+)$', '(\\d+)\.jpg$']:
            matches = re.search(regex, item.url)
            if matches:
                url = 'http://memegenerator.net/instance/'+matches.group(1)
                break
    elif item.domain == 'troll.me':
        url = item.url
    else:
        return None

    # load the page and extract the meme name
    try:
        page = urllib2.urlopen(url)
        soup = BeautifulSoup(page)

        if (item.domain in ['quickmeme.com', 'qkme.me'] or
                item.domain.endswith('.qkme.me')):
            return soup.find_all(id='meme_name')[0].text
        elif item.domain.endswith('memegenerator.net'):
            result = soup.find_all(attrs={'class': 'rank'})[0]
            matches = re.search('#\\d+ (.+)$', result.text)
            return matches.group(1)
        elif item.domain == 'troll.me':
            matches = re.search('^.+?\| (.+?) \|.+?$', soup.title.text)
            return matches.group(1)
    except Exception as e:
        logging.warning('  WARNING: %s', e)
    return None


def elapsed_since(start_time):
    """Returns a timedelta for how much time has passed since start_time."""
    elapsed = time() - start_time
    return timedelta(seconds=elapsed)


def condition_complexity(condition):
    """Returns a value representing how difficult a condition is to check."""
    complexity = 0

    # approving, removing, or setting flair requires a request
    if condition.action in ('approve', 'remove', 'set_flair'):
        complexity += 1

    # meme_name requires an external site page load
    if condition.attribute == 'meme_name':
        complexity += 1

    # checking user requires a page load
    if (condition.is_gold is not None or
            condition.link_karma is not None or
            condition.comment_karma is not None or
            condition.combined_karma is not None or
            condition.account_age is not None):
        complexity += 1

    if condition.comment is not None:
        # commenting+distinguishing requires 2 requests
        if condition.comment_method == 'comment':
            complexity += 2
        else:
            complexity += 1

    # add complexities of all sub-conditions too
    for sub in condition.additional_conditions:
        complexity += condition_complexity(sub)

    return complexity


def get_subreddits_for_queue(sr_dict, cond_dict, queue):
    """Returns a list of subreddits for a particular item queue."""
    relevant_subreddits = set()

    for subreddit in sr_dict.values():
        if queue == 'report':
            if subreddit.auto_reapprove:
                relevant_subreddits.add(subreddit.name)
                continue
        elif queue == 'comment':
            if subreddit.reported_comments_only:
                continue

        if len(cond_dict[subreddit.name.lower()][queue]) > 0:
            relevant_subreddits.add(subreddit.name)

    return list(relevant_subreddits)


def check_queues(sr_dict, cond_dict):
    """Checks all the queues for new items to process."""
    global r

    for queue in QUEUES:
        subreddits = get_subreddits_for_queue(sr_dict, cond_dict, queue)
        if not subreddits:
            continue

        # issues with request being too long at multireddit of ~3000 chars
        # so split into multiple checks if it's longer than that
        # split comment checks into groups of max 40 subreddits as well
        multireddits = []
        current_multi = []
        current_len = 0
        for sub in subreddits:
            if (current_len > 3000 or
                    queue == 'comment' and len(current_multi) >= 40):
                multireddits.append(current_multi)
                current_multi = []
                current_len = 0
            current_multi.append(sub)
            current_len += len(sub) + 1
        multireddits.append(current_multi)

        # fetch and process the items for each multireddit
        for multi in multireddits:
            if queue == 'report':
                report_backlog_limit = timedelta(
                        hours=int(cfg_file.get('reddit',
                                               'report_backlog_limit_hours')))
                stop_time = datetime.utcnow() - report_backlog_limit
            else:
                stop_time = max([getattr(sr, 'last_'+queue)
                                 for sr in sr_dict.values()
                                 if sr.name in multi])

            queue_subreddit = r.get_subreddit('+'.join(multi))
            if queue_subreddit:
                queue_method = getattr(queue_subreddit, QUEUES[queue])
                items = queue_method(limit=1000)
                check_items(queue, items, sr_dict, cond_dict, stop_time)


def main():
    logging.config.fileConfig(path_to_cfg)
    start_utc = datetime.utcnow()
    start_time = time()

    global r
    try:
        r = praw.Reddit(user_agent=cfg_file.get('reddit', 'user_agent'))
        logging.info('Logging in as %s', cfg_file.get('reddit', 'username'))
        r.login(cfg_file.get('reddit', 'username'),
            cfg_file.get('reddit', 'password'))
        log_request('login')

        subreddits = session.query(Subreddit).filter(
                        Subreddit.enabled == True).all()
        # force population of _mod_subs
        list(r.get_subreddit('mod').get_spam(limit=1))
        log_request('listing')
        log_request('mod_subs', len(r.user._mod_subs) / 100 + 1)

        # build sr_dict including only subs both in db and _mod_subs
        sr_dict = dict()
        cond_dict = dict()
        for subreddit in subreddits:
            if subreddit.name.lower() in r.user._mod_subs:
                sr_dict[subreddit.name.lower()] = subreddit
                conditions = subreddit.conditions.all()
                cond_dict[subreddit.name.lower()] = {
                    'report': filter_conditions('report', conditions),
                    'spam': filter_conditions('spam', conditions),
                    'submission': filter_conditions('submission', conditions),
                    'comment': filter_conditions('comment', conditions) }

    except Exception as e:
        logging.error('  ERROR: %s', e)

    check_queues(sr_dict, cond_dict)

    # respond to modmail
    try:
        respond_to_modmail(r.get_mod_mail(), start_utc)
    except Exception as e:
        logging.error('  ERROR: %s', e)

    logging.info('Completed full run in %s (%s due to reddit requests - %s)',
                    elapsed_since(start_time),
                    timedelta(seconds=sum(log_request.counts.values())*2),
                    log_request.counts)


if __name__ == '__main__':
    main()
