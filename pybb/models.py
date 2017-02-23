# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import re
import datetime
import os.path
import uuid
import math
from decimal import Decimal

from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import connection, IntegrityError
from django.db.models.aggregates import Max, Min, Count
from django.db.models.expressions import F
from django.core.exceptions import ValidationError
from django.core.urlresolvers import reverse
from django.db import models, transaction, DatabaseError
from django.utils.encoding import python_2_unicode_compatible, force_unicode, \
                                  smart_unicode
from django.utils.functional import cached_property
from django.utils.html import strip_tags, strip_spaces_between_tags, \
                              linebreaks
from django.utils.translation import ugettext_lazy as _, ungettext as _n
from django.utils.timezone import now as tznow
from django.forms import ValidationError

try:
    from hashlib import sha1
except ImportError:
    from sha import sha as sha1

from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.models import User, AnonymousUser
from django.core.urlresolvers import reverse
from django.apps import apps
from django.contrib.auth.management import create_permissions, _get_all_permissions
from django.template.defaultfilters import date as django_date_filter
from django.conf import settings

from sorl.thumbnail import ImageField

from pybb.compat import get_user_model_path, get_username_field, get_atomic_func, slugify
from pybb import defaults
from pybb.profiles import PybbProfile
from pybb.util import unescape, FilePathGenerator, _get_markup_formatter
from pybb.permissions import (pybb_can_view_forum, pybb_can_administer_forum,
                              pybb_can_add_forum_topic,
                              pybb_can_add_forum_post, pybb_get_visible_forums,
                              pybb_get_forums_with_perm)

from annoying.fields import AutoOneToOneField


# None is safe as default since django settings always have LANGUAGES, MEDIA_ROOT and SECRET_KEY variable set
LANGUAGES = settings.LANGUAGES
MEDIA_ROOT = settings.MEDIA_ROOT
SECRET_KEY = settings.SECRET_KEY
MEDIA_URL = settings.MEDIA_URL


#noinspection PyUnusedLocal
def get_file_path(instance, filename, to='pybb/avatar'):
    """
    This function generate filename with uuid4
    it's useful if:
    - you don't want to allow others to see original uploaded filenames
    - users can upload images with unicode in filenames wich can confuse browsers and filesystem
    """
    ext = filename.split('.')[-1]
    filename = "%s.%s" % (uuid.uuid4(), ext)
    return os.path.join(to, filename)


class RootCategory(models.Model):
    """
    Root object for permissions, which apply to all categories and forums, which inherit permissions

    There should be only one RootCategory object.
    """
    name = models.CharField(_('Name'), max_length=80, default="RootCategory")

    _cached_object = None

    @classmethod
    def get_object(cls):
        if not cls._cached_object:
            cls._cached_object = cls.objects.all()[0]
        return cls._cached_object

    @classmethod
    def reset_cache(cls):
        cls._cached_object = None

    class Meta(object):
        verbose_name = _('Root Category')
        verbose_name_plural = _('Root Category')
        permissions = (
            ('view_forum', 'Can view forums'),
            ('add_forum_topic', 'Can add topics to forums'),
            ('add_forum_post', 'Can add posts to forums'),
            ('administer_forum', 'Can administer forums'),
        )

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        count = RootCategory.objects.count()
        if (self.pk is None and count > 0) or (not self.pk is None and count > 1):
            raise Exception("RootCategory is a singleton")

        super(RootCategory, self).save(*args, **kwargs)


@python_2_unicode_compatible
class Category(models.Model):
    name = models.CharField(_('Name'), max_length=80)
    position = models.IntegerField(_('Position'), blank=True, default=0)
    inherits_permissions = models.BooleanField(_('Inherits Permissions'), default=True)
    hidden = models.BooleanField(_('Hidden'), default=False,
                                 help_text=_('If checked, this category will be visible only for staff'))
    slug = models.SlugField(_("Slug"), max_length=255, unique=True)

    def get_visible_forums(self, user):
        if isinstance(user, AnonymousUser):
            cached_attr_name = "_visible_forums_by_anonymous" # same cached name as below
        else:
            cached_attr_name = "_visible_forums_by_%d" % user.id # same cached name as below

        if not hasattr(self, cached_attr_name):
            setattr(self, cached_attr_name, pybb_get_visible_forums(user, self))
        return getattr(self, cached_attr_name)

    def set_visible_forums_filter_for_user(self, visible_forums_filter, user):
        if isinstance(user, AnonymousUser):
            cached_attr_name = "_visible_forums_by_anonymous" # same cached name as above
        else:
            cached_attr_name = "_visible_forums_by_%d" % user.id # same cached name as above

        visible_forums_in_category = []
        for forum in self.forums.all():
            if forum.id in visible_forums_filter:
                visible_forums_in_category.append(forum.pk)

        setattr(self, cached_attr_name, visible_forums_in_category)

    @property
    def root_category(self):
        return RootCategory.get_object()

    class Meta(object):
        ordering = ['position']
        verbose_name = _('Category')
        verbose_name_plural = _('Categories')
        permissions = (
            ('view_forum', 'Can view forums in Category'),
            ('add_forum_topic', 'Can add topics to forums in Category'),
            ('add_forum_post', 'Can add posts to forums in Category'),
            ('administer_forum', 'Can administer forums in Category'),
        )

    def __str__(self):
        return self.name

    def forum_count(self):
        return self.forums.all().count()

    def get_absolute_url(self):
        if defaults.PYBB_NICE_URL:
            return reverse('pybb:category', kwargs={'slug': self.slug, })
        return reverse('pybb:category', kwargs={'pk': self.id})

    @property
    def topics(self):
        return Topic.objects.filter(forum__category=self).select_related()

    @property
    def posts(self):
        return Post.objects.filter(topic__forum__category=self).select_related()


@python_2_unicode_compatible
class Forum(models.Model):
    category = models.ForeignKey(Category, related_name='forums', verbose_name=_('Category'))
    parent = models.ForeignKey('self', related_name='child_forums', verbose_name=_('Parent forum'),
                               blank=True, null=True)
    name = models.CharField(_('Name'), max_length=80)
    position = models.IntegerField(_('Position'), blank=True, default=0)
    description = models.TextField(_('Description'), blank=True)
    avatar = ImageField(_('Avatar'), blank=True, null=True, upload_to='forum_avatar')
    inherits_permissions = models.BooleanField(_('Inherits Permissions'), default=True)
    moderators = models.ManyToManyField(get_user_model_path(), blank=True, verbose_name=_('Moderators'))
    updated = models.DateTimeField(_('Updated'), blank=True, null=True)
    post_count = models.IntegerField(_('Post count'), blank=True, default=0)
    topic_count = models.IntegerField(_('Topic count'), blank=True, default=0)
    hidden = models.BooleanField(_('Hidden'), default=False)
    readed_by = models.ManyToManyField(get_user_model_path(), through='ForumReadTracker', related_name='readed_forums')
    headline = models.TextField(_('Headline'), blank=True, null=True)
    slug = models.SlugField(verbose_name=_("Slug"), max_length=255)

    class Meta(object):
        ordering = ['position']
        verbose_name = _('Forum')
        verbose_name_plural = _('Forums')
        unique_together = ('category', 'slug')
        permissions = (
            ('view_forum', 'Can view Forum'),
            ('administer_forum', 'Can administer Forum'),
            ('add_forum_topic', 'Can add topics to Forum'),
            ('add_forum_post', 'Can add posts to Forum'),
        )

    def __str__(self):
        return force_unicode(self.name)

    # method from custom pybb v0.6
    def update_counters(self):
        """Calculates and saves topic count and last post ID."""
        self.topic_count = Topic.objects.filter(forum=self).count()
        self.save()

        tracker = self.get_tracker()
        tracker.update_last_visible_post()
        tracker.save()

    # method from original pybb v0.18.4
    #def update_counters(self):
    #    self.topic_count = Topic.objects.filter(forum=self).count()
    #    if self.topic_count:
    #        posts = Post.objects.filter(topic__forum_id=self.id)
    #        self.post_count = posts.count()
    #        if self.post_count:
    #            try:
    #                last_post = posts.order_by('-created', '-id')[0]
    #                self.updated = last_post.updated or last_post.created
    #            except IndexError:
    #                pass
    #    else:
    #        self.post_count = 0
    #    self.save()

    def get_absolute_url(self):
        if defaults.PYBB_NICE_URL:
            return reverse('pybb:forum', kwargs={'slug': self.slug, 'category_slug': self.category.slug})
        return reverse('pybb:forum', kwargs={'pk': self.id})

    @property
    def posts(self):
        return Post.objects.filter(topic__forum=self).select_related()

    @cached_property
    def last_post(self):
        return self.get_last_post()

    def get_tracker(self):
        """Gets (and creates) :class:`ForumTracker` for this topic."""
        tracker, created = ForumTracker.objects.get_or_create(forum=self)
        return tracker

    def get_last_post(self):
        if not hasattr(self, "_last_post"):
            last_post_id = Post.objects.filter(topic__forum=self).aggregate(Max('id'))['id__max']
            if last_post_id:
                self._last_post = Post.objects.get(pk=last_post_id)
            else:
                self._last_post = None
        return self._last_post

    def get_last_visible_post(self):
        if not hasattr(self, "_last_visible_post"):
            tracker = self.get_tracker()
            if tracker:
                self._last_visible_post = tracker.last_visible_post
            else:
                self._last_visible_post = None
        return self._last_visible_post

    def get_last_post_visible_by_user(self, user):
        if isinstance(user, AnonymousUser):
            cached_attr_name = "_last_post_visible_by_anonymous"
        else:
            cached_attr_name = "_last_post_visible_by_%d" % user.id

        if not hasattr(self, cached_attr_name):
            if self.can_be_administered_by_user(user):
                last_post_id = Post.objects.filter(topic__forum=self).aggregate(Max('id'))['id__max']
            else:
                last_post_id = self.get_last_visible_post()

            if last_post_id:
                setattr(self, cached_attr_name, Post.objects.get(pk=last_post_id))
            else:
                setattr(self, cached_attr_name, None)

        return getattr(self, cached_attr_name)

    def new_posts_for_user(self, user):
        if isinstance(user, AnonymousUser):
            # Anonymous user
            return False

        last_post = self.get_last_visible_post()
        if last_post is None:
            # Forum empty
            return False

        return True
        #@TODO figure out forum tracking
        #try:
        #    forum_read_mark = ForumReadTracker.objects.get(forum=self, user=user)
        #    return forum_read_mark.time_stamp < last_post.created
        #except ObjectDoesNotExist as ex:
            # No record for this form and user. So forum never visited before
        #    return True

    def can_be_administered_by_user(self, user):
        if isinstance(user, AnonymousUser):
            cached_attr_name = "_can_be_administered_by_anonymous"
        else:
            cached_attr_name = "_can_be_administered_by_%d" % user.id

        if not hasattr(self, cached_attr_name):
            setattr(self, cached_attr_name, pybb_can_administer_forum(user, self))
        return getattr(self, cached_attr_name)

    def can_user_add_topic(self, user):
        if isinstance(user, AnonymousUser):
            cached_attr_name = "_can_user_add_topic_anonymous"
        else:
            cached_attr_name = "_can_user_add_topic_%d" % user.id

        if not hasattr(self, cached_attr_name):
            setattr(self, cached_attr_name, pybb_can_add_forum_topic(user, self))
        return getattr(self, cached_attr_name)

    def can_user_add_post(self, user):
        if isinstance(user, AnonymousUser):
            cached_attr_name = "_can_user_add_post_anonymous"
        else:
            cached_attr_name = "_can_user_add_post_%d" % user.id

        if not hasattr(self, cached_attr_name):
            setattr(self, cached_attr_name, pybb_can_add_forum_post(user, self))
        return getattr(self, cached_attr_name)

    def get_parents(self):
        """
        Used in templates for breadcrumb building
        """
        parents = [self.category]
        parent = self.parent
        while parent is not None:
            parents.insert(1, parent)
            parent = parent.parent
        return parents


@python_2_unicode_compatible
class ForumSubscription(models.Model):

    TYPE_NOTIFY = 1
    TYPE_SUBSCRIBE = 2
    TYPE_CHOICES = (
        (TYPE_NOTIFY, _('be notified only when a new topic is added')),
        (TYPE_SUBSCRIBE, _('be auto-subscribed to topics')),
    )

    user = models.ForeignKey(get_user_model_path(), on_delete=models.CASCADE,
        related_name='forum_subscriptions+', verbose_name=_('Subscriber'))
    forum = models.ForeignKey(Forum, 
        related_name='subscriptions+', verbose_name=_('Forum'))
    type = models.PositiveSmallIntegerField(
        _('Subscription type'), choices=TYPE_CHOICES,
        help_text=_((
            'The auto-subscription works like you manually subscribed to watch each topic :\n'
            'you will be notified when a topic will receive an answer. \n'
            'If you choose to be notified only when a new topic is added. It means'
            'you will be notified only once when the topic is created : '
            'you won\'t be notified for the answers.'
        )), )

    class Meta(object):
        verbose_name = _('Subscription to forum')
        verbose_name_plural = _('Subscriptions to forums')
        unique_together = ('user', 'forum',)

    def __str__(self):
        return '%(user)s\'s subscription to "%(forum)s"' % {'user': self.user,
                                                            'forum': self.forum}

    def save(self, all_topics=False, **kwargs):
        if all_topics and self.type == self.TYPE_SUBSCRIBE:
            old = None if not self.pk else ForumSubscription.objects.get(pk=self.pk)
            if not old or old.type != self.type :
                topics = Topic.objects.filter(forum=self.forum).exclude(subscribers=self.user)
                self.user.subscriptions.add(*topics)
        super(ForumSubscription, self).save(**kwargs)

    def delete(self, all_topics=False, **kwargs):
        if all_topics:
            topics = Topic.objects.filter(forum=self.forum, subscribers=self.user)
            self.user.subscriptions.remove(*topics)
        super(ForumSubscription, self).delete(**kwargs)


class AbstractInteraction(models.Model):
    """Abstract model that defines properties and methods that are common to
    user interactions, such as topics and posts.
    """
    hidden = models.BooleanField(_('hidden'), default=False)

    @property
    def is_hidden(self):
        return self.hidden

    def set_hidden(self, bool_hidden):
        """Hides or unhides post and handles topic post count. Immediately
        updates record in database.

        Also fires 'post_hidden' signal.
        """
        self.hidden = bool_hidden
        self.__class__.objects.filter(pk=self.pk).update(hidden=self.hidden)

    def hide(self):
        return self.set_hidden(True)

    def unhide(self):
        return self.set_hidden(False)

    class Meta:
        abstract = True


@python_2_unicode_compatible
class Topic(AbstractInteraction):
    class Status:
        OPEN = 0
        LOCKED = 1
        MOVED = 2

    class Importance:
        NORMAL = 0
        STICKY = 1
        ANNOUNCEMENT = 2

    class Activity:
        ACTIVE = 2
        STALE = 1
        INACTIVE = 0

    STATUS_CHOICES = (
        (Status.OPEN, _('Open')),
        (Status.LOCKED, _('Locked')),
        (Status.MOVED, _('Moved')),
    )
    IMPORTANCE_CHOICES = (
        (Importance.NORMAL, _('Normal')),
        (Importance.STICKY, _('Sticky')),
        (Importance.ANNOUNCEMENT, _('Announcement')),
    )

    POLL_TYPE_NONE = 0
    POLL_TYPE_SINGLE = 1
    POLL_TYPE_MULTIPLE = 2

    POLL_TYPE_CHOICES = (
        (POLL_TYPE_NONE, _('None')),
        (POLL_TYPE_SINGLE, _('Single answer')),
        (POLL_TYPE_MULTIPLE, _('Multiple answers')),
    )

    forum = models.ForeignKey(Forum, related_name='topics', verbose_name=_('Forum'))
    name = models.CharField(_('Subject'), max_length=255)
    created = models.DateTimeField(_('Created'), null=True, db_index=True)
    updated = models.DateTimeField(_('Updated'), null=True, db_index=True)
    user = models.ForeignKey(get_user_model_path(), verbose_name=_('User'))
    username_display = models.CharField(_('Display username'), blank=True, null=True, max_length=255)
    views = models.IntegerField(_('Views count'), blank=True, default=0)
    importance = models.IntegerField(
        _('Importance'),
        default=0,
        choices=IMPORTANCE_CHOICES
    )
    status = models.SmallIntegerField(
        _('Status'),
        default=0,
        choices=STATUS_CHOICES
    )
    topic_after_move = models.ForeignKey('self', related_name='topic_before_move', verbose_name=_('Moved topic'),
                                         null=True, default=None)  # contains topic reference if status == 2
    sticky = models.BooleanField(_('Sticky'), default=False)
    closed = models.BooleanField(_('Closed'), default=False)
    subscribers = models.ManyToManyField(get_user_model_path(), related_name='subscriptions',
                                         verbose_name=_('Subscribers'), blank=True)
    post_count = models.IntegerField(_('Post count'), blank=True, default=0)
    readed_by = models.ManyToManyField(get_user_model_path(), through='TopicReadTracker', related_name='readed_topics')
    on_moderation = models.BooleanField(_('On moderation'), default=False)
    poll_type = models.IntegerField(_('Poll type'), choices=POLL_TYPE_CHOICES, default=POLL_TYPE_NONE)
    poll_question = models.TextField(_('Poll question'), blank=True, null=True)
    slug = models.SlugField(verbose_name=_("Slug"), max_length=255)
    related_object_content_type = models.ForeignKey(ContentType, null=True, blank=True)
    related_object_id = models.IntegerField(null=True, blank=True)
    related_object = GenericForeignKey('related_object_content_type', 'related_object_id')

    class Meta(object):
        ordering = ['-created']
        verbose_name = _('Topic')
        verbose_name_plural = _('Topics')
        unique_together = ('forum', 'slug')

    def __str__(self):
        return self.name

    @cached_property
    def head(self):
        """
        Get first post and cache it for request
        """
        if not hasattr(self, "_head"):
            try:
                self._head = self.posts.filter(hidden=False).order_by('pk')[0]
            except IndexError:
                self._head = None
        return self._head

    @property
    def last_post(self):
        return self.get_last_post()

    def get_last_post(self):
        """
        Get last post and cache it
        """
        if not hasattr(self, "_last_post"):
            self._get_post_summary()
            if self._last_post_id:
                self._last_post = Post.objects.get(pk=self._last_post_id)
            else:
                self._last_post = None
        return self._last_post

    def get_absolute_url(self):
        if defaults.PYBB_NICE_URL:
            return reverse('pybb:topic', kwargs={'slug': self.slug, 'forum_slug': self.forum.slug, 'category_slug': self.forum.category.slug})
        return reverse('pybb:topic', kwargs={'pk': self.id})

    def save(self, *args, **kwargs):
        if self.id is None:
            self.created = self.updated = tznow()

        forum_changed = False
        old_topic = None
        if self.id is not None:
            old_topic = Topic.objects.get(id=self.id)
            if self.forum != old_topic.forum:
                forum_changed = True

        super(Topic, self).save(*args, **kwargs)

        if forum_changed:
            old_topic.forum.update_counters()
            self.forum.update_counters()

    @property
    def is_open(self):
        return self.status == self.Status.OPEN

    @property
    def is_locked(self):
        return self.status == self.Status.LOCKED

    @property
    def is_moved(self):
        return self.status == self.Status.MOVED

    def delete(self, using=None):
        super(Topic, self).delete(using)
        self.forum.update_counters()

    def update_counters(self):
        self.post_count = self.posts.count()
        # force cache overwrite to get the real latest updated post
        if hasattr(self, 'last_post'):
            del self.last_post
        if self.last_post:
            self.updated = self.last_post.updated or self.last_post.created
        self.save()

    def get_parents(self):
        """
        Used in templates for breadcrumb building
        """
        parents = self.forum.get_parents()
        parents.append(self.forum)
        return parents

    def poll_votes(self):
        if self.poll_type != self.POLL_TYPE_NONE:
            return PollAnswerUser.objects.filter(poll_answer__topic=self).count()
        else:
            return None

    @property
    def post_count(self):
        return self.get_tracker().visible_post_count

    def get_tracker(self):
        """Gets (and creates) :class:`TopicTracker` for this topic."""
        if not hasattr(self, '_topic_tracker'):
            self._topic_tracker, new = TopicTracker.objects.get_or_create(topic=self)
        return self._topic_tracker

    def invalidate_tracker_cache(self):
        """Delete memoized TopicTracker in :attr:`_topic_tracker` and related
        attributes.
        """
        if hasattr(self, '_topic_tracker'):
            del self._topic_tracker

        if hasattr(self, '_visible_post_count'):
            del self._visible_post_count

        if hasattr(self, '_last_visible_post'):
            del self._last_visible_post

            # This is an optimization in order to reuse cached properties on the forum object

    def set_parent_forum(self, parent_forum):
        if parent_forum.id != self.forum_id:
            raise ValueError("forums id's must be equal")
        self._parent_forum = parent_forum

    def can_parent_forum_be_administered_by_user(self, user):
        if hasattr(self, "_parent_forum"):
            return self._parent_forum.can_be_administered_by_user(user)
        else:
            return self.forum.can_be_administered_by_user(user)

    # Post count and last post - if one of them in needed then most probably the other one too
    # So why not getting them in the same query
    def _get_post_summary(self):
        if not hasattr(self, "_last_post_id") and not hasattr(self, "_post_count"):
            results = Post.objects.filter(topic=self).aggregate(Max('id'))
            self._last_post_id = results['id__max']

    # Post count and last post visible by the current user - if one of them in needed then most probably
    # the other one too. So why not getting them in the same query
    def get_visible_post_summary(self):
        if not hasattr(self, "_last_visible_post_id") and not hasattr(self, "_visible_post_count"):
            try:
                tracker = self.get_tracker()
            except ObjectDoesNotExist:
                results = Post.objects.filter(topic=self, hidden=False).aggregate(Max('id'), Count('id'))
                self._last_visible_post_id = results['id__max']
                self._visible_post_count = results['id__count']
            else:
                self._last_visible_post_id = tracker.last_visible_post_id
                self._visible_post_count = tracker.visible_post_count

    def get_unread_post_summary(self, user):
        if not hasattr(self, "_first_unread_post") and not hasattr(self, "_unread_post_count"):
            if self.new_posts_for_user(user):
                last_viewed = self.get_last_post_viewed_by_user(user)
                if last_viewed is None:
                    last_id = 0
                else:
                    last_id = last_viewed.id
                results = Post.objects.filter(topic=self, hidden=False, id__gt=last_id).aggregate(Min('id'),
                                                                                                  Count('id'))
                if results['id__count'] > 0:
                    self._first_unread_post = Post.objects.get(pk=results['id__min'])
                    self._unread_post_count = results['id__count']
                else:
                    self._first_unread_post_id = None
                    self._unread_post_count = 0
            else:
                self._first_unread_post_id = None
                self._unread_post_count = 0

    def get_first_unread_post(self, user):
        if not hasattr(self, "_first_unread_post"):
            self.get_unread_post_summary(user)

        return self._first_unread_post

    def get_unread_post_count(self, user):
        if not hasattr(self, "_unread_post_count"):
            self.get_unread_post_summary(user)

        return self._unread_post_count

    @property
    def last_post(self):
        return self.get_last_post()

    def get_last_post(self):
        """
        Get last post and cache it
        """
        if not hasattr(self, "_last_post"):
            self._get_post_summary()
            if self._last_post_id:
                self._last_post = Post.objects.get(pk=self._last_post_id)
            else:
                self._last_post = None
        return self._last_post

    def get_visible_post_count(self):
        cached_attr_name = "_visible_post_count"

        if not hasattr(self, cached_attr_name):
            # post_count = Post.objects.filter(topic=self, hidden=False).aggregate(Count('id'))['id__count']
            self.get_visible_post_summary()
            setattr(self, cached_attr_name, self._visible_post_count)

        return getattr(self, cached_attr_name)

    @property
    def last_visible_post(self):
        return self.get_last_visible_post()

    def get_last_visible_post(self):
        cached_attr_name = "_last_visible_post"

        if not hasattr(self, cached_attr_name):
            tracker = self.get_tracker()
            setattr(self, cached_attr_name, tracker.last_visible_post)

        return getattr(self, cached_attr_name)

    def get_last_post_visible_by_user(self, user):
        if user is None:
            return self.get_last_visible_post()
        elif isinstance(user, AnonymousUser):
            cached_attr_name = "_last_post_visible_by_anonymous"
        else:
            cached_attr_name = "_last_post_visible_by_%d" % user.id

        if not hasattr(self, cached_attr_name):
            if self.can_parent_forum_be_administered_by_user(user):
                setattr(self, cached_attr_name, self.get_last_post())
            else:
                setattr(self, cached_attr_name, self.get_last_visible_post())

        return getattr(self, cached_attr_name)

    def get_post_count_visible_by_user(self, user):
        if user is None:
            return self.get_visible_post_count()
        elif isinstance(user, AnonymousUser):
            cached_attr_name = "_post_count_visible_by_anonymous"
        else:
            cached_attr_name = "_post_count_visible_by_%d" % user.id

        if not hasattr(self, cached_attr_name):
            if self.can_parent_forum_be_administered_by_user(user):
                post_count = self.post_count
            else:
                post_count = self.get_visible_post_count()
            setattr(self, cached_attr_name, post_count)

        return getattr(self, cached_attr_name)

    def get_last_post_viewed_by_user(self, user):
        if user is None:
            return None

        cached_attr_name = "_last_post_viewed"
        last_post_viewed = None

        if not hasattr(self, cached_attr_name):
            if user.is_authenticated():
                try:
                    topic_view_mark = TopicViewTracker.objects.get(topic=self, user=user)
                except ObjectDoesNotExist as ex:
                    # No record for this topic and user, which means that the
                    # topic has never been visited
                    pass
                else:
                    last_post_viewed = Post.objects.select_related('user').get(
                        pk=topic_view_mark.highest_viewed_post_id)
            setattr(self, cached_attr_name, last_post_viewed)

        return getattr(self, cached_attr_name)

    def new_posts_for_user(self, user):
        if user is None or isinstance(user, AnonymousUser):
            # Anonymous user
            return False

        last_post_viewed_by_user = self.get_last_post_viewed_by_user(user)
        if last_post_viewed_by_user is None:
            # No TopicViewTracker record for this user and topic
            activity_state = self.get_activity_state()
            if activity_state <= Topic.Activity.STALE:
                # Do not display older topics as having new posts
                return False
            else:
                return True

        last_post_visible = self.get_last_visible_post()

        if last_post_visible is None:
            return False

        return last_post_viewed_by_user.pk < last_post_visible.pk

    @property
    def related_object_name(self):
        if self.related_object and defaults.PYBB_TOPIC_RELATED_OBJECT_MODEL_FIELD:
            return getattr(self.related_object, defaults.PYBB_TOPIC_RELATED_OBJECT_MODEL_FIELD)
        return ''

    def importance_formatted(self):
        """Returns a (localized) string describing the 'importance' of the
        topic.
        """
        for option in self.IMPORTANCE_CHOICES:
            if option[0] == self.importance:
                return option[1]
        return ''

    def record_view_by_user(self, user):
        try:
            TopicViewTracker.record_view_by_user(self, user)
        except IntegrityError, e:
            # Log error & ignore, because it doesn't directly affect this
            # request
            # log.warning(e)
            pass

    def get_last_page_url(self, anchor=True):
        url = reverse('pybb:topic', kwargs={
            'pk': self.id,
            'page': 'last'
        })
        if anchor:
            url += '#last'
        return url

    @classmethod
    def get_related_object_info(cls):
        related_object_type = None
        related_object_choices = None
        if defaults.PYBB_TOPIC_RELATED_OBJECT_APP_LABEL and defaults.PYBB_TOPIC_RELATED_OBJECT_MODEL and defaults.PYBB_TOPIC_RELATED_OBJECT_MODEL_FIELD:
            related_object_type = ContentType.objects.get(app_label=defaults.PYBB_TOPIC_RELATED_OBJECT_APP_LABEL,
                                                          model=defaults.PYBB_TOPIC_RELATED_OBJECT_MODEL)
            related_object_class = related_object_type.model_class()
            related_object_choices = []
            for row in related_object_class.objects.all():
                related_object_choices.append((row.pk, getattr(row, defaults.PYBB_TOPIC_RELATED_OBJECT_MODEL_FIELD)))
            if related_object_choices:
                related_object_choices.insert(0, ('', '----------'))

        return related_object_type, related_object_choices

    def is_user_subscribed(self, user):
        """Has `user` subscribed to updates to this topic?"""
        return User.objects.filter(pk=user.pk, subscriptions=self.pk).count() == 1

    def increase_post_count(self, amount=1):
        """Increments the post count by `amount`."""
        TopicTracker.objects. \
            filter(topic=self.pk). \
            update(visible_post_count=F('visible_post_count') + amount)

    def decrease_post_count(self, amount=1):
        """Decreases the post count by `amount`."""
        self.increase_post_count(amount=-amount)

    def lock(self):
        """Sets Topic status to locked (preventing any further posts)."""
        self.status = Topic.Status.LOCKED

    def unlock(self):
        """Sets Topic status to unlocked."""
        self.status = Topic.Status.OPEN

    @classmethod
    def get_user_cooldown(cls, user):
        """Returns the number of seconds remaining in the `user` topic cooldown.
        The cooldown is measured by the creation date of the user's last :class:`Topic`

        :returns: > 0 if the cooldown is still active (and posting should be denied), 0 if cooldown has expired
        """
        # Get the last Topic date
        try:
            # @TODO If this query becomes too slow for users with many topics,
            # consider storing the 'last topic date' in a seperate model
            last_topic = cls.objects.filter(user=user).only('created').order_by('-created')[0]
        except IndexError:
            # User's first topic, allow
            return 0

        allow_from_date = last_topic.created + \
                          datetime.timedelta(seconds=defaults.PYBB_ADD_TOPIC_COOLDOWN)

        now = datetime.datetime.now()
        return 0 if now >= allow_from_date else (allow_from_date - now).seconds

    def get_number_of_posts_per_user(self, visible_only=True):
        """Returns a dictionary of user IDs with the number of posts they've
        made as value.

        Use `visible_only` to filter between visible and all posts.
        """
        qs = Post.objects.filter(topic=self)
        if visible_only:
            qs = qs.filter(hidden=False)
        results = qs.values('user_id').annotate(Count('id'))

        # Non-pythonic necessity: if we're using sqlite3 as a backend, group
        # the results manually since it doesn't handle qs.values() like MySQL
        # (and presumably(!) others) do
        if getattr(connection.client, 'executable_name', '') == 'sqlite3':
            processed_results = {}
            for result in results:
                processed_results.setdefault(result['user_id'], 0)
                processed_results[result['user_id']] += result['id__count']
            return processed_results

        return dict([(x.get('user_id'), x.get('id__count')) for x in results])

    def get_activity_state(self):
        """Returns a value from :class:`Topic.Acitivity` indicating the state
        of the activity in this topic.
        """
        last_post_date = self.get_tracker().last_visible_post_date
        if not last_post_date:
            # No tracker, so we're going to assume that we're dealing with an
            # an empty, inactive topic
            return Topic.Activity.INACTIVE

        now = datetime.datetime.now()
        if now - defaults.PYBB_TOPIC_ACTIVITY_STALE > last_post_date:
            return Topic.Activity.INACTIVE
        elif now - defaults.PYBB_TOPIC_ACTIVITY_ACTIVE > last_post_date and \
                                now - defaults.PYBB_TOPIC_ACTIVITY_STALE < last_post_date:
            return Topic.Activity.STALE
        else:
            return Topic.Activity.ACTIVE


class RenderableItem(AbstractInteraction):
    """
    Base class for models that has markup, body, body_text and body_html fields.
    """

    class Meta(object):
        abstract = True

    body = models.TextField(_('Message'))
    body_html = models.TextField(_('HTML version'))
    body_text = models.TextField(_('Text version'))

    def render(self):
        sanitized_field = models.TextField()
        sanitized_field.attname = 'body'
        sanitized_body = sanitized_field.pre_save(self, False)

        if self.enable_bbcode:
            # Replace smilies with BBcode
            for smiley in defaults.PYBB_SMILES.keys():
                sanitized_body = re.sub(
                    '\B' + re.escape(smiley),
                    '[smiley %s]' % smiley,
                    sanitized_body
                )

            self.body_html = defaults.PYBB_MARKUP_ENGINES[defaults.PYBB_MARKUP](sanitized_body)

            # If this post is being edited outside of the 'edit ' time window
            if self.pk and defaults.PYBB_EDIT_POST_NO_NOTE_TIME > 0:
                now = datetime.datetime.now()
                note_from_time = now - datetime.timedelta(seconds=defaults.PYBB_EDIT_POST_NO_NOTE_TIME)

                if note_from_time > self.created:
                    # 'No edit note time' has expired
                    self.body_html += '<p class="edit_note">' + _(
                        'Post was edited on %(date)s by %(edit_username)s'
                    ) % {
                                                                    'date': django_date_filter(now,
                                                                                               settings.DATETIME_FORMAT),
                                                                    'edit_username': self.edit_user.get_profile().name
                                                                } + '</p>'

            # Remove whitespace between HTML tags
            self.body_html = strip_spaces_between_tags(self.body_html.strip())

        else:
            self.body_html = linebreaks(sanitized_body)


@python_2_unicode_compatible
class Post(RenderableItem):
    class Status:
        OPEN = 0
        LOCKED = 1

    STATUS_CHOICES = (
        (Status.OPEN, _('Open')),
        (Status.LOCKED, _('Locked')),
    )

    topic = models.ForeignKey(Topic, related_name='posts', verbose_name=_('Topic'))
    user = models.ForeignKey(get_user_model_path(), related_name='posts', verbose_name=_('User'))
    username_display = models.CharField(_('Display username'), blank=True, null=True, max_length=255)
    edit_user = models.ForeignKey(User, verbose_name=_('Edited by'), null=True)
    status = models.SmallIntegerField(_('Edit status'), default=0, choices=STATUS_CHOICES)
    enable_bbcode = models.BooleanField(_('Enable BBCode'), default=True)
    created = models.DateTimeField(_('Created'), blank=True, db_index=True)
    updated = models.DateTimeField(_('Updated'), blank=True, null=True, db_index=True)
    user_ip = models.GenericIPAddressField(_('User IP'), blank=True, null=True, default='0.0.0.0')
    on_moderation = models.BooleanField(_('On moderation'), default=False)

    class Meta(object):
        ordering = ['created']
        verbose_name = _('Post')
        verbose_name_plural = _('Posts')

    @property
    def is_open(self):
        return self.status == self.Status.OPEN

    @property
    def is_locked(self):
        return self.status == self.Status.LOCKED

    @property
    def body_text(self):
        """Virtual field that returns the contents of :attr:`body_html` without
        HTML tags.
        """
        return unescape(strip_tags(self.body_html))

    def summary(self):
        limit = 50
        tail = len(self.body) > limit and '...' or ''
        return self.body[:limit] + tail

    def short_summary(self):
        limit = 20
        tail = len(self.body_text) > limit and '...' or ''
        return self.body_text[:limit] + tail

    def __str__(self):
        return self.short_summary()

    @cached_property
    def is_topic_head(self):
        return self.pk and self.topic.head.pk == self.pk

    def save(self, *args, **kwargs):
        created_at = tznow()
        if self.created is None:
            self.created = created_at
        self.render()

        new = self.pk is None

        topic_changed = False
        old_post = None
        if not new:
            old_post = Post.objects.get(pk=self.pk)
            if old_post.topic != self.topic:
                topic_changed = True

        super(Post, self).save(*args, **kwargs)

        # If post is topic head and moderated, moderate topic too
        if self.topic.head == self and not self.on_moderation and self.topic.on_moderation:
            self.topic.on_moderation = False

        self.topic.update_counters()
        self.topic.forum.update_counters()

        if topic_changed:
            old_post.topic.update_counters()
            old_post.topic.forum.update_counters()

    @classmethod
    def get_user_cooldown(cls, user):
        """Returns the number of seconds remaining in the `user` post cooldown.
        The cooldown is measured by the creation date of the user's last :class:`Post`

        :returns: > 0 if the cooldown is still active (and posting should be denied), 0 if cooldown has expired
        """
        # Get the last post made by the user
        try:
            last_post = UserTracker.get_tracker_for_user(user).last_visible_post
        except ObjectDoesNotExist, e:
            last_post = None

        if last_post is None:
            # User's first post, allow
            return 0

        allow_from_date = last_post.created + \
                          datetime.timedelta(seconds=defaults.PYBB_ADD_POST_COOLDOWN)

        now = datetime.datetime.now()
        return 0 if now >= allow_from_date else (allow_from_date - now).seconds

    def get_absolute_url(self):
        return reverse('pybb:post', kwargs={'pk': self.id})

    def get_in_topic_url(self):
        """Returns the URL to the topic / page on which the post is placed
        (even if it's hidden).
        """
        pass

    def delete(self, *args, **kwargs):
        self_id = self.id
        head_post_id = self.topic.posts.order_by('created', 'id')[0].id

        if self_id == head_post_id:
            self.topic.delete()
        else:
            super(Post, self).delete(*args, **kwargs)
            self.topic.update_counters()
            self.topic.forum.update_counters()

    def get_parents(self):
        """
        Used in templates for breadcrumb building
        """
        return self.topic.forum.category, self.topic.forum, self.topic,

    @property
    def page_number(self):
        """Returns the page number this post is on as an integer."""
        values = self.__class__.objects.filter(topic=self.topic, hidden=False).order_by('pk'). \
            values_list('pk', flat=True)
        try:
            post_index = list(values).index(self.pk)
            return max(1, int(math.ceil(
                Decimal(post_index) / defaults.PYBB_TOPIC_PAGE_SIZE
            )))
        except ValueError:
            # Post could not be found (could be hidden or deleted)
            return None

    @property
    def is_first_post(self):
        """Returns if this post is the first post of the topic it is in.
        """
        if not self.pk:
            return False

        first_post = self.topic.head
        return first_post and first_post.pk == self.pk


class PostReportReason(models.Model):
    title = models.CharField(_('Reason for reporting a post'), max_length=255)

    class Meta(object):
        ordering = ['title']
        verbose_name = _('Post Report Reason')
        verbose_name_plural = _('Post Report Reasons')


class PostReport(models.Model):
    post = models.ForeignKey(Post, verbose_name=_('Post'))
    reporter = models.ForeignKey(User, verbose_name=_('Reported by'), related_name='reporter')
    reason = models.ForeignKey(PostReportReason, verbose_name=_('Reason'), default=1)
    message = models.TextField(_('Message'))
    moderator = models.ForeignKey(User, verbose_name=_('Processed by'), related_name='moderator', blank=True, null=True)
    moderator_comment = models.TextField(_('Moderator\'s comment'), blank=True, null=True)
    created = models.DateTimeField(_('Created'), auto_now_add=True)
    updated = models.DateTimeField(_('Updated'), auto_now=True, null=False)
    STATUS = (
        (0, 'Reported'),
        (1, 'Processed'),
    )
    status = models.SmallIntegerField(_('Status'), default=0, choices=STATUS, db_index=True)

    class Meta(object):
        ordering = ['-created']
        verbose_name = _('Reported Post')
        verbose_name_plural = _('Reported Posts')

    def summary(self):
        limit = 50
        tail = len(self.message) > limit and '...' or ''
        return self.message[:limit] + tail

    @classmethod
    def get_post_reports_for_user(cls, user, include_processed=False):
        """Returns list of PostReport objects that have reported posts in
        Forums of which `user` is a moderator.

        If `include_processed` is True, PostReports that have been marked as
        processed are returned as well.
        """
        # Get a list of forum IDs that this user is a moderator of
        administrated_forums = pybb_get_forums_with_perm(user, 'administer_forum')

        post_reports = cls.objects.all().order_by('-created').\
                select_related('post').\
                filter(post__topic__forum__pk__in=administrated_forums)

        if not include_processed:
            post_reports = post_reports.filter(status=0)

        return post_reports

    def get_absolute_url(self):
        return reverse('pybb:post_report', kwargs={'pk': self.id})

    def __str__(self):
        return self.summary()


class Profile(PybbProfile):
    """
    Profile class that can be used if you doesn't have
    your site profile.
    """
    user = AutoOneToOneField(get_user_model_path(), related_name='pybb_profile', verbose_name=_('User'))

    class Meta(object):
        verbose_name = _('Profile')
        verbose_name_plural = _('Profiles')

    def get_absolute_url(self):
        return reverse('pybb:user', kwargs={'id': self.user.id})

    def get_display_name(self):
        return self.user.get_username()

    @property
    def name(self):
        if self.nickname:
            return self.nickname
        else:
            return self.user.username


class UserSetting(models.Model):
    """Storage for user settings related to this forum.

    This model differs from :class:`PybbProfile` because this one *assumes* that
    there already is a project-wide UserProfile set for Django auth. That
    profile would contains general user (meta)data like the user's avatar,
    signature, post count. This model only stores forum-specific data.
    """

    user = models.OneToOneField(
        User,
        related_name='pybb_user_settings',
        verbose_name=_('User'),
        primary_key=True
    )

    autosubscribe = models.BooleanField(_('Automatically subscribe'),
        help_text=_('Automatically subscribe to topics that you answer'),
        default=defaults.PYBB_DEFAULT_AUTOSUBSCRIBE)
    show_signatures = models.BooleanField(_('Show signatures'), blank=False,
        default=True)
    posts_per_page = models.IntegerField(
        _('Posts per page'),
        blank=False,
        default=defaults.PYBB_TOPIC_PAGE_SIZE,
        choices=defaults.PYBB_TOPIC_PAGE_SIZE_CHOICES
    )
    rank = models.CharField(
        _('Rank'),
        max_length=32,
        blank=True
    )

    @classmethod
    def get_setting_for_user(cls, user, setting_attr):
        """Returns `setting_attr` for `user`.

        If the user isn't authenticated or doesn't have settings stored, it
        returns the default value.
        """
        user_settings = None

        if user.is_authenticated():
            try:
                user_settings = user.pybb_user_settings
            except cls.DoesNotExist:
                # Use default settings
                pass

        if not user_settings:
            # For users without a settings record and anonymous users
            user_settings = user.pybb_user_settings = UserSetting()

        return getattr(user_settings, setting_attr)

    def __str__(self):
        return unicode(self.user)


class AbstractTracker(models.Model):
    last_visible_post = models.ForeignKey(
        Post,
        verbose_name=_('Last visible post'),
        null=True,
        on_delete=models.SET_NULL
    )
    last_visible_post_date = models.DateTimeField(
        _('Last visible post\'s date'),
        null=True
    )

    def get_post_info_queryset(self):
        """Should return QuerySet containing the :class:`pybb.models.Post`s
        that can be used to calculate which one the newest for our related
        object (forum or topic).
        """
        raise NotImplementedError

    def save_last_post_info(self, last_visible_post=None):
        """Updates :attr:`last_visible_post` ID to `last_visible_post` or the
        post with the highest ID in/by the object being tracked.
        """
        self.update_last_visible_post(last_visible_post)
        return self.save()

    def update_last_visible_post(self, last_visible_post=None):
        """Updates :attr:`last_visible_post` with `last_visible_post` or
        the newest Post, selected via :meth:`get_post_info_queryset()`.
        """
        if not last_visible_post:
            results = self.get_post_info_queryset().aggregate(Max('id'))
            # Skip update for topics that are, for whatever reason, without posts
            if results['id__max']:
                last_visible_post = Post.objects.get(pk=results['id__max'])

        if last_visible_post:
            self.last_visible_post = last_visible_post
            self.last_visible_post_date = last_visible_post.created

    class Meta:
        abstract = True


class TopicTracker(AbstractTracker):
    class Meta(object):
        verbose_name = _('Topic tracker')
        verbose_name_plural = _('Topic trackers')

    topic = models.OneToOneField(Topic, verbose_name=_('Tracked topic'), related_name='tracker')
    view_count = models.PositiveIntegerField(verbose_name=_('Topic views'), default=0)
    visible_post_count = models.PositiveIntegerField(verbose_name=_('Visible post count'), default=0)

    def get_post_info_queryset(self):
        return Post.objects.filter(topic=self.topic_id, hidden=False)

    @classmethod
    def increment_view_count(cls, topic):
        topic_tracker, new = TopicTracker.objects.get_or_create(topic=topic)
        if new:
            topic_tracker.save_last_post_info()

        TopicTracker.objects.filter(topic=topic).update(view_count=F('view_count') + 1)

    def save_last_post_info(self, last_visible_post=None, *args, **kwargs):
        if last_visible_post and last_visible_post.topic_id != self.topic_id:
            raise ValueError('The post belongs to another topic')

        return super(TopicTracker, self).save_last_post_info(last_visible_post,
                                                          *args, **kwargs)

    def update_visible_post_count(self):
        """
        Updates :attr:`visible_post_count` by executing a COUNT() query.
        """
        self.visible_post_count = Post.objects.filter(topic=self.topic, hidden=False).count()


class ForumTracker(AbstractTracker):
    """Stores temporary / generated data related to :class:`pybb.models.Forum`.
    """
    forum = models.OneToOneField(
        Forum,
        verbose_name=_('Forum'),
        related_name='forum_tracker'
    )

    def get_post_info_queryset(self):
        return Post.objects.filter(topic__forum=self.forum, hidden=False)


class UserTracker(AbstractTracker):
    """Keeps track of the last post made by a `User`. This is used to determine
    if users are posting too quickly (cooldown).
    """

    user = models.OneToOneField(
        User,
        verbose_name=_('User'),
        related_name='user_tracker'
    )

    @classmethod
    def get_tracker_for_user(cls, user):
        """Returns (and creates, if necessary) a `UserTracker` object for
        `user`.
        """
        tracker, created = cls.objects.get_or_create(user=user)
        return tracker


class TopicViewTracker(models.Model):
    class Meta(object):
        verbose_name = _('Topic view tracker')
        verbose_name_plural = _('Topic view trackers')
        unique_together = ('user', 'topic')

    user = models.ForeignKey(User, blank=False)
    topic = models.ForeignKey(Topic, blank=False)
    highest_viewed_post = models.ForeignKey(Post, related_name='view_tracker', blank=False)

    @classmethod
    def record_view_by_user(cls, topic, user, post=None):
        if isinstance(user, AnonymousUser):
            return

        if post is None:
            post = topic.last_visible_post

        if post is None:
            return

        topic_activity = topic.get_activity_state()

        try:
            topic_view_tracked = TopicViewTracker.objects.get(topic=topic, user=user)
        except ObjectDoesNotExist:
            # Only create view trackers for active topics
            if topic_activity == Topic.Activity.ACTIVE:
                topic_view_tracked = TopicViewTracker.objects.create(
                    topic=topic, user=user, highest_viewed_post=post
                )
        else:
            # Update existing trackers for stale or active topics
            if topic_activity >= Topic.Activity.STALE:
                if post.id == topic_view_tracked.highest_viewed_post_id:
                    return
                topic_view_tracked.highest_viewed_post = topic.last_visible_post
                topic_view_tracked.save()


class Attachment(models.Model):
    class Meta(object):
        verbose_name = _('Attachment')
        verbose_name_plural = _('Attachments')

    post = models.ForeignKey(Post, verbose_name=_('Post'), related_name='attachments')
    size = models.IntegerField(_('Size'))
    file = models.FileField(_('File'),
                            upload_to=FilePathGenerator(to=defaults.PYBB_ATTACHMENT_UPLOAD_TO))

    def save(self, *args, **kwargs):
        self.size = self.file.size
        super(Attachment, self).save(*args, **kwargs)

    def size_display(self):
        size = self.size
        if size < 1024:
            return '%db' % size
        elif size < 1024 * 1024:
            return '%dKb' % int(size / 1024)
        else:
            return '%.2fMb' % (size / float(1024 * 1024))


class TopicReadTrackerManager(models.Manager):
    def get_or_create_tracker(self, user, topic):
        """
        Correctly create tracker in mysql db on default REPEATABLE READ transaction mode

        It's known problem when standrard get_or_create method return can raise exception
        with correct data in mysql database.
        See http://stackoverflow.com/questions/2235318/how-do-i-deal-with-this-race-condition-in-django/2235624
        """
        is_new = True
        sid = transaction.savepoint(using=self.db)
        try:
            with get_atomic_func()():
                obj = TopicReadTracker.objects.create(user=user, topic=topic)
            transaction.savepoint_commit(sid)
        except DatabaseError:
            transaction.savepoint_rollback(sid)
            obj = TopicReadTracker.objects.get(user=user, topic=topic)
            is_new = False
        return obj, is_new


class TopicReadTracker(models.Model):
    """
    Save per user topic read tracking
    """
    user = models.ForeignKey(get_user_model_path(), blank=False, null=False)
    topic = models.ForeignKey(Topic, blank=True, null=True)
    time_stamp = models.DateTimeField(auto_now=True)

    objects = TopicReadTrackerManager()

    class Meta(object):
        verbose_name = _('Topic read tracker')
        verbose_name_plural = _('Topic read trackers')
        unique_together = ('user', 'topic')


class ForumReadTrackerManager(models.Manager):
    def get_or_create_tracker(self, user, forum):
        """
        Correctly create tracker in mysql db on default REPEATABLE READ transaction mode

        It's known problem when standrard get_or_create method return can raise exception
        with correct data in mysql database.
        See http://stackoverflow.com/questions/2235318/how-do-i-deal-with-this-race-condition-in-django/2235624
        """
        is_new = True
        sid = transaction.savepoint(using=self.db)
        try:
            with get_atomic_func()():
                obj = ForumReadTracker.objects.create(user=user, forum=forum)
            transaction.savepoint_commit(sid)
        except DatabaseError:
            transaction.savepoint_rollback(sid)
            is_new = False
            obj = ForumReadTracker.objects.get(user=user, forum=forum)
        return obj, is_new


class ForumReadTracker(models.Model):
    """
    Save per user forum read tracking
    """
    user = models.ForeignKey(get_user_model_path(), blank=False, null=False)
    forum = models.ForeignKey(Forum, blank=True, null=True)
    time_stamp = models.DateTimeField(auto_now=True)

    objects = ForumReadTrackerManager()

    class Meta(object):
        verbose_name = _('Forum read tracker')
        verbose_name_plural = _('Forum read trackers')
        unique_together = ('user', 'forum')


@python_2_unicode_compatible
class PollAnswer(models.Model):
    topic = models.ForeignKey(Topic, related_name='poll_answers', verbose_name=_('Topic'))
    text = models.CharField(max_length=255, verbose_name=_('Text'))

    class Meta:
        verbose_name = _('Poll answer')
        verbose_name_plural = _('Polls answers')

    def __str__(self):
        return self.text

    def votes(self):
        return self.users.count()

    def votes_percent(self):
        topic_votes = self.topic.poll_votes()
        if topic_votes > 0:
            return 1.0 * self.votes() / topic_votes * 100
        else:
            return 0


@python_2_unicode_compatible
class PollAnswerUser(models.Model):
    poll_answer = models.ForeignKey(PollAnswer, related_name='users', verbose_name=_('Poll answer'))
    user = models.ForeignKey(get_user_model_path(), related_name='poll_answers', verbose_name=_('User'))
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Poll answer user')
        verbose_name_plural = _('Polls answers users')
        unique_together = (('poll_answer', 'user', ), )

    def __str__(self):
        return '%s - %s' % (self.poll_answer.topic, self.user)


def create_or_check_slug(instance, model, **extra_filters):
    """
    returns a unique slug

    :param instance : target instance
    :param model: needed as instance._meta.model is available since django 1.6
    :param extra_filters: filters needed for Forum and Topic for their unique_together field
    """
    initial_slug = instance.slug or slugify(instance.name)
    count = -1
    last_count_len = 0
    slug_is_not_unique = True
    while slug_is_not_unique:
        count += 1

        if count >= defaults.PYBB_NICE_URL_SLUG_DUPLICATE_LIMIT:
            msg = _('After %(limit)s attemps, there is not any unique slug value for "%(slug)s"')
            raise ValidationError(msg % {'limit': defaults.PYBB_NICE_URL_SLUG_DUPLICATE_LIMIT,
                                         'slug': initial_slug})

        count_len = len(str(count))

        if last_count_len != count_len:
            last_count_len = count_len
            filters = {'slug__startswith': initial_slug[:(254-count_len)], }
            if extra_filters:
                filters.update(extra_filters)
            objs = model.objects.filter(**filters).exclude(pk=instance.pk)
            slug_list = [obj.slug for obj in objs]

        if count == 0:
            slug = initial_slug
        else:
            slug = '%s-%d' % (initial_slug[:(254-count_len)], count)
        slug_is_not_unique = slug in slug_list

    return slug


# This model is used during migration from phpBB to PyBB
class PostPhpBB(models.Model):
    phpbb_body = models.TextField('phpBB Markup')   # User input
    body = models.TextField('Markup version')   # User input in BBCode
    body_html = models.TextField('HTML version', null=True)     # Cached HTML
    #bbcode_uid = models.CharField('BBCode UID', max_length=8)
    topic_id = models.IntegerField('Topic ID')
    enable_bbcode = models.BooleanField('Enable BBCode', default=True)

    class Meta:
        managed = False
        db_table = 'pybb_post'
        ordering = ['id']

class PybbUser(User):
    """Proxy model for creating a (limited) admin interface for users, which
    has its own set of permissions to allow forum moderators (limited) access
    to user records.
    """

    class Meta:
        proxy = True
