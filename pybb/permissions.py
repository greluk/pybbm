# -*- coding: utf-8 -*-
"""
Extensible permission system for pybbm
"""

from __future__ import unicode_literals
from django.db.models import Q
from django.contrib.auth.models import AnonymousUser, User, Group
from django.conf import settings
from django.core.cache import cache

from guardian.shortcuts import get_perms, get_objects_for_user, \
    get_objects_for_group

from pybb import defaults, util


# For some reason, Django caching iterates through all users (thus 90k for IG forum)
# which makes this method unusable
def pybb_has_perm(user, forum, codename):
    """
    Check if the user has given permission for a specific forum.
    """
    if not forum.inherits_permissions:
        # No permissions inherited, return result for this forum
        return codename in get_perms(user, forum)

    if not forum.category.inherits_permissions or forum.category.root_category is None:
        # Find out whether permissions granted for the parent category for this forum
        return codename in get_perms(user, forum.category) or codename in get_perms(user, forum)

    # Find out whether permissions granted for root category, the parent category for this forum
    return codename in get_perms(user, forum.category.root_category) or codename in get_perms(user, forum.category) or codename in get_perms(user, forum)


def pybb_can_view_forum(user, forum):
    """
    Check if the user can read topics in a specific forum.
    """
    # see comment at pybb_has_perm
    #return user.is_superuser or pybb_has_perm(user, forum, 'view_forum')
    return user.is_superuser or forum.pk in pybb_get_forums_with_perm(user, 'view_forum')


def pybb_can_administer_forum(user, forum):
    """
    Check if the user can administer topics in a specific forum.
    """
    # see comment at pybb_has_perm
    # return user.is_superuser or pybb_has_perm(user, forum, 'administer_forum')
    return user.is_superuser or forum.pk in pybb_get_administered_forums(user)


def pybb_get_administered_forums(user):
    """
    Returns a list of :class:`pybb.models.Forum` IDs that `user` has
    administrative permissions for.
    """
    return pybb_get_forums_with_perm(user, 'administer_forum')


def pybb_can_add_forum_topic(user, forum):
    """
    Check if the user can create topics in a specific forum.
    """
    # see comment at pybb_has_perm
    # return user.is_superuser or pybb_has_perm(user, forum, 'add_forum_topic')
    return user.is_superuser or forum.pk in pybb_get_forums_with_perm(user, 'add_forum_topic')


def pybb_can_add_forum_post(user, forum):
    """
    Check if the user can create replies in a specific forum.
    """
    # see comment at pybb_has_perm
    # return user.is_superuser or pybb_has_perm(user, forum, 'add_forum_post')
    return user.is_superuser or forum.pk in pybb_get_forums_with_perm(user, 'add_forum_post')


def pybb_has_view_perm(forum, root_categories_with_perm, categories_with_perm, forums_with_perm):
    """
    Check if the user has given permission for a specific forum.
    """
    if not forum.inherits_permissions:
        # No permissions inherited, return result for this forum
        return forum.id in forums_with_perm

    if not forum.category.inherits_permissions or forum.category.root_category is None:
        # Find out whether permissions granted for the parent category for this forum
        return forum.category.id in categories_with_perm or forum.id in forums_with_perm

    # Find out whether permissions granted for root category, the parent category for this forum and the forum
    return forum.category.root_category in root_categories_with_perm or forum.category_id in categories_with_perm or forum.id in forums_with_perm


def pybb_get_visible_forums(user, category=None):
    """Returns a list of :class:`pybb.model.Forum` IDs that the `user` has the
    `view_forum` permission to.
    """
    return pybb_get_forums_with_perm(user, 'view_forum', category)

def pybb_get_forums_with_perm(user, perm, category=None):
    """Returns a list of PKs to :class:`pybb.model.Forum` objects that the `user` has the
    `perm` to.

    This function assumes that every logged-in user is part of the User group.
    """
    from pybb.models import RootCategory, Category, Forum

    all_forums = category and category.forums.all() or Forum.objects.all().select_related('category')
    category_string = getattr(category, 'pk', None) or 'all'

    if not user.is_authenticated():
        # get_objects_for_user() raises exception for AnonymousUser
        #user = User.objects.filter(pk=settings.ANONYMOUS_USER_ID)[0]
        user = User.objects.get(pk=settings.ANONYMOUS_USER_ID)
        user_group_forum_ids = []
    else:
        # Get all the permissions for the User group, which we assume every
        # authenticated user is in
        user_groups = list(user.groups.all())
        user_groups.append(Group.objects.get(name=defaults.PYBB_DEFAULT_USER_GROUP))
        user_groups = sorted(user_groups)

        cache_suffix = '__%s__%s__%s' % (
            perm, category_string, '|'.join([str(x.pk) for x in user_groups])
        )
        user_group_cache_key = 'pybb_user_group_forums' + cache_suffix
        user_group_forum_ids = cache.get(user_group_cache_key)

        if user_group_forum_ids is None:
            user_group_forum_ids = []

            for user_group in user_groups:
                root_categories_with_perm = get_objects_for_group(user_group, perm, klass=RootCategory)
                categories_with_perm = [c.id for c in get_objects_for_group(user_group, perm, klass=Category)]
                forums_with_perm = get_objects_for_group(user_group, perm, klass=Forum)

                user_group_forums = pybb_filter_invisible_forums(
                    all_forums,
                    root_categories_with_perm,
                    categories_with_perm,
                    forums_with_perm
                )
                user_group_forum_ids.extend([x.pk for x in user_group_forums])

            user_group_forum_ids = list(set(user_group_forum_ids))
            cache.set(user_group_cache_key, user_group_forum_ids, defaults.PYBB_PERMISSION_CACHE_TIME)

    # Look up user (and non-User-group) specific permissions
    cache_suffix = '__%s__%s__%s' % (
        str(user.pk), perm, category_string
    )
    specific_cache_key = 'pybb_specific_forums' + cache_suffix
    specific_forum_ids = cache.get(specific_cache_key)

    if specific_forum_ids is None:
        root_categories_with_perm = get_objects_for_user(user, perm, klass=RootCategory)
        categories_with_perm = [c.id for c in get_objects_for_user(user, perm, klass=Category)]
        forums_with_perm = get_objects_for_user(user, perm, klass=Forum)

        specific_forums = pybb_filter_invisible_forums(
            all_forums,
            root_categories_with_perm,
            categories_with_perm,
            forums_with_perm
        )
        specific_forum_ids = [x.pk for x in specific_forums]

        cache.set(specific_cache_key, specific_forum_ids, defaults.PYBB_PERMISSION_CACHE_TIME)

    # Combine results and dedupe
    forum_ids = set(user_group_forum_ids + specific_forum_ids)

    return [x for x in forum_ids]

def pybb_filter_invisible_forums(forums_to_filter, root_categories, categories, forums):
    """Filters `forums_to_filter` by removing those which are invisible, according to
    `root_categories`, `categories` and `forums`.

    This is used in conjunction with :func:`pybb_get_forums_with_perm`, which
    retrieves all forums and (root)categories for which the user and/or its
    groups have the requested permission to. This function ensures only visible
    forums are returned.
    """
    visible_forums = []
    for forum in forums_to_filter:
        if forum in forums or pybb_has_view_perm(forum ,root_categories,
                                                 categories, forums):
            visible_forums.append(forum)
    return visible_forums


class DefaultPermissionHandler(object):
    """ 
    Default Permission handler. If you want to implement custom permissions (for example,
    private forums based on some application-specific settings), you can inherit from this
    class and override any of the `filter_*` and `may_*` methods. Methods starting with
    `may` are expected to return `True` or `False`, whereas methods starting with `filter_*`
    should filter the queryset they receive, and return a new queryset containing only the
    objects the user is allowed to see.
    
    To activate your custom permission handler, set `settings.PYBB_PERMISSION_HANDLER` to
    the full qualified name of your class, e.g. "`myapp.pybb_adapter.MyPermissionHandler`".    
    """
    #
    # permission checks on categories
    #
    def filter_categories(self, user, qs):
        """ return a queryset with categories `user` is allowed to see """
        if user.is_superuser or user.is_staff:
            # FIXME: is_staff only allow user to access /admin but does not mean user has extra
            # permissions on pybb models. We should add pybb perm test
            return qs
        return qs.filter(hidden=False)

    def may_view_category(self, user, category):
        """ return True if `user` may view this category, False if not """
        if user.is_superuser or user.is_staff:
            # FIXME: is_staff only allow user to access /admin but does not mean user has extra
            # permissions on pybb models. We should add pybb perm test
            return True
        return not category.hidden

    # 
    # permission checks on forums
    # 
    def filter_forums(self, user, qs):
        """ return a queryset with forums `user` is allowed to see """
        if user.is_superuser or user.is_staff:
            # FIXME: is_staff only allow user to access /admin but does not mean user has extra
            # permissions on pybb models. We should add pybb perm test
            return qs
        return qs.filter(Q(hidden=False) & Q(category__hidden=False))

    def may_view_forum(self, user, forum):
        """ return True if user may view this forum, False if not """
        if user.is_superuser or user.is_staff:
            # FIXME: is_staff only allow user to access /admin but does not mean user has extra
            # permissions on pybb models. We should add pybb perm test
            return True
        return forum.hidden == False and forum.category.hidden == False 

    def may_create_topic(self, user, forum):
        """ return True if `user` is allowed to create a new topic in `forum` """
        if user.is_superuser:
            return True
        return user.has_perm('pybb.add_post')

    #
    # permission checks on topics
    # 
    def filter_topics(self, user, qs):
        """ return a queryset with topics `user` is allowed to see """
        if user.is_superuser:
            return qs
        if user.has_perm('pybb.change_topic'):
            # if I can edit, I can view
            return qs
        if not user.is_staff:
            # FIXME: is_staff only allow user to access /admin but does not mean user has extra
            # permissions on pybb models. We should add pybb perm test
            qs = qs.filter(Q(forum__hidden=False) & Q(forum__category__hidden=False))
        if user.is_authenticated():
            qs = qs.filter(
                # moderator can view on_moderation
                Q(forum__moderators=user) |
                # author can view on_moderation only if there is one post in the topic
                # (mean that post is owned by author)
                Q(user=user, post_count=1) |
                # posts not on_moderation are accessible
                Q(on_moderation=False)
            )
        else:
            qs = qs.filter(on_moderation=False)
        return qs.distinct()

    def may_view_topic(self, user, topic):
        """ return True if user may view this topic, False otherwise """
        if self.may_moderate_topic(user, topic):
            # If i can moderate, it means I can view.
            return True
        if topic.on_moderation:
            if not topic.head.on_moderation:
                # topic is in general moderation waiting (it has been marked as on_moderation
                # but my post is not on_moderation. So it's a manual action we MUST respect)
                return False
            if topic.head.on_moderation and topic.head.user != user:
                # topic is on moderation because of the first post but this is not my post
                # User must not access to it, only it's author can do in moderation mode
                return False
        # FIXME: is_staff only allow user to access /admin but does not mean user has extra
        # permissions on pybb models. We should add pybb perm test
        return user.is_staff or (not topic.forum.hidden and not topic.forum.category.hidden)

    def may_moderate_topic(self, user, topic):
        if user.is_superuser:
            return True
        if not user.is_authenticated():
            return False
        return user.has_perm('pybb.change_topic') or user in topic.forum.moderators.all()

    def may_close_topic(self, user, topic):
        """ return True if `user` may close `topic` """
        return self.may_moderate_topic(user, topic)

    def may_open_topic(self, user, topic):
        """ return True if `user` may open `topic` """
        return self.may_moderate_topic(user, topic)

    def may_stick_topic(self, user, topic):
        """ return True if `user` may stick `topic` """
        return self.may_moderate_topic(user, topic)

    def may_unstick_topic(self, user, topic):
        """ return True if `user` may unstick `topic` """
        return self.may_moderate_topic(user, topic)

    def may_vote_in_topic(self, user, topic):
        """ return True if `user` may unstick `topic` """
        if topic.poll_type == topic.POLL_TYPE_NONE or not user.is_authenticated():
            return False
        elif user.is_superuser:
            return True
        elif not topic.closed and not user.poll_answers.filter(poll_answer__topic=topic).exists():
            return True
        return False

    def may_create_post(self, user, topic):
        """ return True if `user` is allowed to create a new post in `topic` """

        if user.is_superuser:
            return True
        if not defaults.PYBB_ENABLE_ANONYMOUS_POST and not user.is_authenticated():
            return False
        if not self.may_view_topic(user, topic):
            return False
        if not user.has_perm('pybb.add_post'):
            return False
        if topic.closed or topic.on_moderation:
            return self.may_moderate_topic(user, topic)
        return True


    def may_post_as_admin(self, user):
        """ return True if `user` may post as admin """
        if user.is_superuser:
            return True
        # FIXME: is_staff only allow user to access /admin but does not mean user has extra
        # permissions on pybb models. We should add pybb perm test
        return user.is_staff  

    def may_subscribe_topic(self, user, topic):
        """ return True if `user` is allowed to subscribe to a `topic` """
        return not defaults.PYBB_DISABLE_SUBSCRIPTIONS and user.is_authenticated()

    #
    # permission checks on posts
    #    
    def filter_posts(self, user, qs):
        """ return a queryset with posts `user` is allowed to see """

        # first filter by topic availability
        if user.is_superuser:
            return qs
        if user.has_perm('pybb.change_post'):
            # If I can edit all posts, I can view all posts
            return qs
        if not user.is_staff:
            # remove hidden forum/cats posts
            query = Q(topic__forum__hidden=False, topic__forum__category__hidden=False)
        else:
            query = Q(pk__isnull=False)
        if defaults.PYBB_PREMODERATION:
            # remove moderated posts
            query = query & Q(on_moderation=False, topic__on_moderation=False)
        if user.is_authenticated():
            # cancel previous remove if it's my post, or if I'm moderator of the forum
            query = query | Q(user=user) | Q(topic__forum__moderators=user)
        return qs.filter(query).distinct()

    def may_view_post(self, user, post):
        """ return True if `user` may view `post`, False otherwise """
        if user.is_superuser:
            return True
        if self.may_edit_post(user, post):
            # if I can edit, I can view
            return True
        if defaults.PYBB_PREMODERATION and (post.on_moderation or post.topic.on_moderation):
            return False
        # FIXME: is_staff only allow user to access /admin but does not mean user has extra
        # permissions on pybb models. We should add pybb perm test
        return user.is_staff or (not post.topic.forum.hidden and
                                 not post.topic.forum.category.hidden)

    def may_moderate_post(self, user, post):
        if user.is_superuser:
            return True
        return user.has_perm('pybb.change_post') or self.may_moderate_topic(user, post.topic)
        
    def may_edit_post(self, user, post):
        """ return True if `user` may edit `post` """
        if user.is_superuser:
            return True
        return post.user == user or self.may_moderate_post(user, post)

    def may_delete_post(self, user, post):
        """ return True if `user` may delete `post` """
        if user.is_superuser:
            return True
        if not user.is_authenticated():
            return False
        return (defaults.PYBB_ALLOW_DELETE_OWN_POST and post.user == user) or \
               user.has_perm('pybb.delete_post') or \
               user in post.topic.forum.moderators.all()
        # may_moderate_post does not mean that user is a moderator: a user who is not a moderator
        # may_moderate_post if he has change_post perms. For this reason, we need to check
        # if user is really a post's topic moderator.


    def may_admin_post(self, user, post):
        """ return True if `user` may use the admin interface to administrate the `post` """
        if user.is_superuser:
            return True
        return user.is_staff and user.has_perm('pybb.change_post')

    #
    # permission checks on users
    #
    def may_block_user(self, user, user_to_block):
        """ return True if `user` may block `user_to_block` """
        if user.is_superuser:
            return True
        return user.has_perm('pybb.block_users')

    def may_attach_files(self, user):
        """
        return True if `user` may attach files to posts, False otherwise.
        By default controlled by PYBB_ATTACHMENT_ENABLE setting
        """
        return defaults.PYBB_ATTACHMENT_ENABLE

    def may_create_poll(self, user):
        """
        return True if `user` may add poll to posts, False otherwise.
        By default always True
        """
        return True

    def may_edit_topic_slug(self, user):
        """
        returns True if `user` may choose topic's slug, False otherwise.
        When True adds field slug in the Topic form.
        By default always False
        """
        return False

    def may_change_forum(self, user, forum):
        """
        Returns True if the user has the permissions to add modertors to a forum
        By default True if user can change forum
        """
        if user.is_superuser:
            return True
        return user.has_perm('pybb.change_forum')

    def may_manage_moderators(self, user):
        """ return True if `user` may manage moderators"""
        if user.is_superuser:
            return True
        # FIXME: is_staff only allow user to access /admin but does not mean user has extra
        # permissions on pybb models. We should add pybb perm test
        return user.is_staff

perms = util.resolve_class(defaults.PYBB_PERMISSION_HANDLER)
