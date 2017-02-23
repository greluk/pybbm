# -*- coding: utf-8 -*-

from __future__ import unicode_literals
import re
import inspect
from datetime import datetime

from django import forms, template
from django.forms import ValidationError
from django.core.exceptions import FieldError, PermissionDenied
from django.forms.models import inlineformset_factory, BaseInlineFormSet
from django.template.context import Context
from django.utils.safestring import mark_safe
from django.utils.decorators import method_decorator
from django.utils.text import Truncator
from django.utils.translation import ugettext, ugettext_lazy
from django.utils.timezone import now as tznow
from django.utils.translation import ugettext_lazy as _, ungettext as _n
from django.conf import settings

from pybb import compat, defaults, util, permissions
from pybb.models import Topic, Post, Attachment, PollAnswer, \
    ForumSubscription, Category, Forum, create_or_check_slug, \
    Profile, PostReport, PostReportReason
from pybb.permissions import *


User = compat.get_user_model()
username_field = compat.get_username_field()

MEDIA_ROOT = settings.MEDIA_ROOT


class TopicForm(forms.ModelForm):
    name = forms.CharField(label=_('Subject'))
    body = forms.CharField(label=_('Message'), widget=forms.Textarea)
    related_object = forms.ChoiceField(label=_('Related object'), required=False)
    subscribe = forms.BooleanField(label=_('Notify me about new replies'), required=False, initial=True)

    class Meta(object):
        model = Topic
        fields = ('importance',)
        widgets = {
            'importance': forms.RadioSelect,
        }

    def __init__(self, *args, **kwargs):
        #Move args to kwargs
        if args:
            kwargs.update(dict(zip(inspect.getargspec(super(TopicForm, self).__init__)[0][1:], args)))

        self.instance = kwargs.get('instance', None)
        self.forum = kwargs.pop('forum', None)
        if not self.forum and kwargs.get('instance', None):
            self.forum = self.instance.forum
        if not (self.forum or ('instance' in kwargs)):
            raise ValueError('You should provide forum or instance')

        self.user = kwargs.pop('user', None)
        self.ip = kwargs.pop('ip', None)
        self.preview = kwargs.pop('preview', False)

        self.related_object_type, self.related_object_choices = Topic.get_related_object_info()

        if self.related_object_choices:
            self.declared_fields['related_object'].choices = self.related_object_choices

        self.post_form = None

        super(TopicForm, self).__init__(**kwargs)

        self.fields.keyOrder = ['name']
        if self.related_object_choices:
            self.fields.keyOrder.append('related_object')
        self.fields.keyOrder.append('body')
        self.fields.keyOrder.append('subscribe')
        if self.forum.can_be_administered_by_user(self.user):
            self.fields.keyOrder.append('importance')

        self.aviable_smiles = defaults.PYBB_SMILES
        self.smiles_prefix = defaults.PYBB_SMILES_PREFIX

    def clean(self):
        """Checks if user isn't still on his 'add topic cooldown'."""
        cooldown_remaining = Topic.get_user_cooldown(self.user)

        if not self.instance or not getattr(self.instance, 'pk', None):
            # Adding a new topic: check cooldown
            if cooldown_remaining > 0:
                raise ValidationError(
                    _n(
                        'You have to wait %(seconds)d more second before you can place another topic',
                        'You have to wait %(seconds)d more seconds before you can place another topic',
                        cooldown_remaining
                    ) % {
                        'seconds': cooldown_remaining
                    }
                )

        # Validate post-section of the form when editing the topic. We can only
        # do this when editing because PostForm needs a topic object to
        # function and there is none during the topic add process.
        if self.instance:
            post_instance = self.instance.head
            self.post_form = PostForm(
                user=self.user,
                ip=self.ip,
                instance=post_instance,
                topic=self.instance,
                data={
                    'body': self.cleaned_data.get('body', '')
                }
            )
            post_form_result = self.post_form.is_valid()

            if not post_form_result:
                self.errors.update(self.post_form.errors)

        return super(TopicForm, self).clean()

    def clean_body(self):
        body = self.cleaned_data['body']
        user = self.user or self.instance.user
        BODY_CLEANER = getattr(settings, 'BODY_CLEANER', None)
        if BODY_CLEANER:
            BODY_CLEANER(user, body)
        return body

    def is_valid(self):
        # In case user wants to preview the form, we pretend it is invalid and prepare the post to be
        # displayed in preview as if it was saved
        if self.preview:
            if super(TopicForm, self).is_valid():
                self.preview_post = self.save(commit=False)
                self.preview_post.render()
            else:
                self.preview = False
            return False
        return super(TopicForm, self).is_valid()

    def save(self, commit=True):
        related_object = None
        if self.cleaned_data.get('related_object', None):
            try:
                related_object_pk = int(self.cleaned_data['related_object'].pk)
            except ValueError:
                pass
            else:
                related_object = self.related_object_type.get_object_for_this_type(pk=related_object_pk)

        if self.instance.pk:
            now = datetime.now()
            topic = super(TopicForm, self).save(commit=False)
            topic.related_object = related_object
            if 'name' in self.fields.keys():
                topic.name = self.cleaned_data['name']
            if 'importance' in self.fields.keys():
                topic.importance = self.cleaned_data['importance']
            topic.updated = now

            if self.cleaned_data.get('subscribe', False):
                topic.subscribers.add(self.user)
            else:
                topic.subscribers.remove(self.user)

            if commit:
                topic.save()

            post = topic.head
            post.body = self.cleaned_data['body']
            post.updated = now

            if commit:
                if self.post_form:
                    # Post form has some additional save logic (add edit user,
                    # topic subscription)
                    post = self.post_form.save(commit=True)
                else:
                    post.save()

            return post

        topic = Topic(forum=self.forum, user=self.user, name=self.cleaned_data['name'])
        if self.cleaned_data.has_key('importance'):
            topic.importance=self.cleaned_data['importance']
        topic.related_object = related_object
        if commit:
            topic.save()
            if self.cleaned_data['subscribe']:
                topic.subscribers.add(self.user)
                topic.save()

        post = Post(topic=topic, user=self.user, user_ip=self.ip, body=self.cleaned_data['body'])
        if commit:
            post.save()
        return post


class MoveTopicForm(forms.ModelForm):
    leave_placeholder = forms.BooleanField(label=_('Leave Placeholder'), initial=True, required=False)

    class Meta(object):
        model = Topic
        fields = ()

    def __init__(self, *args, **kwargs):
        #Move args to kwargs
        if args:
            kwargs.update(dict(zip(inspect.getargspec(super(MoveTopicForm, self).__init__)[0][1:], args)))
        self.user = kwargs.pop('user', None)
        self.ip = kwargs.pop('ip', None)
        self.domain = kwargs.pop('domain', '')

        super(MoveTopicForm, self).__init__(**kwargs)

        self.original_forum = self.instance.forum

        visible_forums = []
        forums = Forum.objects.filter(pk__in=pybb_get_visible_forums(self.user))
        for f in forums:
            visible_forums.append((f.id, f.name))

        self.fields['target_forums'] = forms.ChoiceField(label=_('Target forums'), choices=visible_forums)

        #self.declared_fields['target_forums'].choices = visible_forums

        self.fields.keyOrder = ['target_forums', 'leave_placeholder']


    def save(self, commit=True):
        topic = super(MoveTopicForm, self).save(commit=False)
        if 'target_forums' in self.changed_data:
            forum_id = int(self.cleaned_data['target_forums'])
            target_forum = Forum.objects.get(pk=forum_id)
            if not pybb_can_administer_forum(self.user, target_forum):
                raise PermissionDenied

            topic.forum = target_forum
            topic.save()

            # Unsubscribe all users that aren't allowed to read the target
            # forum
            list_subscribers = list(topic.subscribers.all())
            for subscriber in list_subscribers:
                if not pybb_can_view_forum(subscriber, target_forum):
                    topic.subscribers.remove(subscriber)

            if self.cleaned_data['leave_placeholder']:
                t = template.loader.get_template('pybb/messages/topic_moved.html')
                post_body = mark_safe(t.render(Context({'topic': topic, 'domain':self.domain})))

                placeholder_topic = Topic(forum=self.original_forum,
                                          user=self.user, name=topic.name,
                                          status=2, topic_after_move=topic,
                                          hidden=topic.hidden)
                placeholder_topic.save()

                post = Post(topic=placeholder_topic, user=self.user, user_ip=self.ip, body=post_body)
                post.save()

        return self.instance


class SubscribeToTopicForm(forms.ModelForm):

    class Meta(object):
        model = Topic
        fields = ()

    def __init__(self, *args, **kwargs):
        #Move args to kwargs
        if args:
            kwargs.update(dict(zip(inspect.getargspec(super(SubscribeToTopicForm, self).__init__)[0][1:], args)))
        self.user = kwargs.pop('user', None)

        super(SubscribeToTopicForm, self).__init__(**kwargs)

    def save(self, commit=True):
        topic = super(SubscribeToTopicForm, self).save(commit=False)
        topic.subscribers.add(self.user)
        if commit:
            topic.save()

        return topic


class UnsubscribeFromTopicForm(forms.ModelForm):

    class Meta(object):
        model = Topic
        fields = ()

    def __init__(self, *args, **kwargs):
        #Move args to kwargs
        if args:
            kwargs.update(dict(zip(inspect.getargspec(super(UnsubscribeFromTopicForm, self).__init__)[0][1:], args)))
        self.user = kwargs.pop('user', None)

        super(UnsubscribeFromTopicForm, self).__init__(**kwargs)

    def save(self, commit=True):
        topic = super(UnsubscribeFromTopicForm, self).save(commit=False)
        topic.subscribers.remove(self.user)
        if commit:
            topic.save()

        return topic


class AttachmentForm(forms.ModelForm):
    class Meta(object):
        model = Attachment
        fields = ('file', )

    def clean_file(self):
        if self.cleaned_data['file'].size > defaults.PYBB_ATTACHMENT_SIZE_LIMIT:
            raise forms.ValidationError(ugettext('Attachment is too big'))
        return self.cleaned_data['file']

AttachmentFormSet = inlineformset_factory(Post, Attachment, extra=1, form=AttachmentForm)


class PollAnswerForm(forms.ModelForm):
    class Meta:
        model = PollAnswer
        fields = ('text', )


class BasePollAnswerFormset(BaseInlineFormSet):
    def clean(self):
        forms_cnt = (len(self.initial_forms) + len([form for form in self.extra_forms if form.has_changed()]) -
                     len(self.deleted_forms))
        if forms_cnt > defaults.PYBB_POLL_MAX_ANSWERS:
            raise forms.ValidationError(
                ugettext('You can''t add more than %s answers for poll' % defaults.PYBB_POLL_MAX_ANSWERS))
        if forms_cnt < 2:
            raise forms.ValidationError(ugettext('Add two or more answers for this poll'))


PollAnswerFormSet = inlineformset_factory(Topic, PollAnswer, extra=2, max_num=defaults.PYBB_POLL_MAX_ANSWERS,
                                          form=PollAnswerForm, formset=BasePollAnswerFormset)


class PostForm(forms.ModelForm):
    name = forms.CharField(label=ugettext_lazy('Subject'))
    poll_type = forms.TypedChoiceField(label=ugettext_lazy('Poll type'), choices=Topic.POLL_TYPE_CHOICES, coerce=int)
    poll_question = forms.CharField(
        label=ugettext_lazy('Poll question'),
        required=False,
        widget=forms.Textarea(attrs={'class': 'no-markitup'}))
    slug = forms.CharField(label=ugettext_lazy('Topic slug'), required=False)
    subscribe = forms.BooleanField(
        label=_('Subscribe to future replies in this topic'),
        required=False,
        initial=True
    )

    class Meta(object):
        model = Post
        fields = ('body', 'subscribe')
        widgets = {
            'body': util.get_markup_engine().get_widget_cls(),
        }

    def __init__(self, *args, **kwargs):
        # Move args to kwargs
        if args:
            kwargs.update(dict(zip(inspect.getargspec(super(PostForm, self).__init__)[0][1:], args)))
        self.user = kwargs.pop('user', None)
        self.ip = kwargs.pop('ip', None)
        self.topic = kwargs.pop('topic', None)
        self.forum = kwargs.pop('forum', None)
        self.may_create_poll = kwargs.pop('may_create_poll', True)
        self.may_edit_topic_slug = kwargs.pop('may_edit_topic_slug', False)
        if not self.topic and kwargs.get('instance', None):
            self.topic = kwargs['instance'].topic
        self.preview = kwargs.pop('preview', False)
        if not (self.topic or self.forum or ('instance' in kwargs)):
            raise ValueError('You should provide topic, forum or instance')
            # Handle topic subject, poll type and question if editing topic head

        # Use user's subscription to topic as initial value for 'subscribe'
        if self.user and (not 'initial' in kwargs or not 'subscribe' in kwargs['initial']):
            kwargs.setdefault('initial', {})['subscribe'] = self.topic.is_user_subscribed(self.user)

        if kwargs.get('instance', None) and (kwargs['instance'].topic.head == kwargs['instance']):
            kwargs.setdefault('initial', {})['name'] = kwargs['instance'].topic.name
            kwargs.setdefault('initial', {})['poll_type'] = kwargs['instance'].topic.poll_type
            kwargs.setdefault('initial', {})['poll_question'] = kwargs['instance'].topic.poll_question

        super(PostForm, self).__init__(**kwargs)

        # remove topic specific fields
        if not (self.forum or (self.instance.pk and (self.instance.topic.head == self.instance))):
            del self.fields['name']
            del self.fields['poll_type']
            del self.fields['poll_question']
            del self.fields['slug']
        else:
            if not self.may_create_poll:
                del self.fields['poll_type']
                del self.fields['poll_question']
            if not self.may_edit_topic_slug:
                del self.fields['slug']

        self.available_smiles = defaults.PYBB_SMILES
        self.smiles_prefix = defaults.PYBB_SMILES_PREFIX

        if self.preview:
            if kwargs['instance']:
                self.preview_body = defaults.PYBB_MARKUP_ENGINES[defaults.PYBB_MARKUP](kwargs['instance'].body)

    def clean_body(self):
        body = self.cleaned_data['body']
        user = self.user or self.instance.user
        BODY_CLEANER = getattr(settings, 'BODY_CLEANER', None)
        if BODY_CLEANER:
            BODY_CLEANER(user, body)
        return body

    def clean(self):
        """Checks if Topic is open and user's post cooldown.
        """
        if self.topic.is_locked and not \
           pybb_can_administer_forum(self.user, self.topic.forum):
            # Disallow non-moderators
            raise ValidationError(_('The topic you are trying to post in is closed'))

        if not self.instance or not getattr(self.instance, 'pk', None):
            # Adding new post: check cooldown
            cooldown_remaining = Post.get_user_cooldown(self.user)

            if cooldown_remaining > 0:
                raise ValidationError(
                    _n(
                        'You have to wait %(seconds)d more second before you can place another post',
                        'You have to wait %(seconds)d more seconds before you can place another post',
                        cooldown_remaining
                    ) % {
                        'seconds': cooldown_remaining
                    }
                )

        return super(PostForm, self).clean()

    def is_valid(self):
        # In case user wants to preview the form, we pretend it is invalid and prepare the post to be
        # displayed in preview as if it was saved
        if self.preview:
            if super(PostForm, self).is_valid():
                self.preview_post = self.save(commit=False)
                self.preview_post.render()
            else:
                self.preview = False
            return False
        return super(PostForm, self).is_valid()

    def save(self, commit=True):
        if self.instance.pk:
            post = super(PostForm, self).save(commit=False)
            if self.user:
                post.user = self.user
            if post.topic.head == post:
                post.topic.name = self.cleaned_data['name']
                if self.may_create_poll:
                    post.topic.poll_type = self.cleaned_data['poll_type']
                    post.topic.poll_question = self.cleaned_data['poll_question']
                post.topic.updated = tznow()
                if commit:
                    post.topic.save()
            post.updated = tznow()
            if commit:
                post.save()
                # Subscribe to topic
                if self.cleaned_data['subscribe']:
                    post.topic.subscribers.add(self.user)
                else:
                    post.topic.subscribers.remove(self.user)
            return post, post.topic

        allow_post = True
        if defaults.PYBB_PREMODERATION:
            allow_post = defaults.PYBB_PREMODERATION(self.user, self.cleaned_data['body'])
        if self.forum:
            topic = Topic(
                forum=self.forum,
                user=self.user,
                name=self.cleaned_data['name'],
                poll_type=self.cleaned_data.get('poll_type', Topic.POLL_TYPE_NONE),
                poll_question=self.cleaned_data.get('poll_question', None),
                slug=self.cleaned_data.get('slug', None),
            )
            if not allow_post:
                topic.on_moderation = True
        else:
            topic = self.topic
        post = Post(user=self.user, user_ip=self.ip, body=self.cleaned_data['body'])
        if not allow_post:
            post.on_moderation = True
        if commit:
            topic.save()
            post.topic = topic
            post.save()
        return post, topic


class PostReportForm(forms.ModelForm):
    report_reason = forms.ChoiceField(label=_('Post reason'))

    class Meta(object):
        model = PostReport
        fields = ('report_reason', 'message')

    def __init__(self, *args, **kwargs):
        #Move args to kwargs
        if args:
            kwargs.update(dict(zip(inspect.getargspec(super(PostReportForm, self).__init__)[0][1:], args)))
        self.reporter = kwargs.pop('reporter', None)
        self.post = kwargs.pop('post', None)
        if not (self.post or ('instance' in kwargs)):
            raise ValueError('You should provide post or instance')

        reason_choices = [('', '-------')]
        for row in PostReportReason.objects.values('id', 'title').all():
            reason_choices.append((row['id'], row['title']))
        self.declared_fields['report_reason'].choices = reason_choices

        super(PostReportForm, self).__init__(**kwargs)

    def save(self, commit=True):
        if self.instance.pk:
            post_report = super(PostReportForm, self).save(commit=False)
            if commit:
                post_report.save()
            return post_report

        report_reason = PostReportReason.objects.get(pk=int(self.cleaned_data['report_reason']))
        post_report = PostReport(post=self.post, reporter=self.reporter, message=self.cleaned_data['message'], reason=report_reason)
        if commit:
            post_report.save()
        return post_report


class InlineModeratePostReportForm(forms.ModelForm):
    """Form to moderate a post that has been reported.

    This form requires an instance (of PostReport) to be passed at initialization.
    """
    hidden = forms.BooleanField(label=_('Hide post'), required=False)
    close_topic = forms.BooleanField(label=_('Close topic'), required=False)
    body = forms.CharField(label=_('Post body'), widget=forms.Textarea)

    def __init__(self, *args, **kwargs):
        if not 'instance' in kwargs or not kwargs['instance'].pk:
            raise ValueError('%s requires a saved instance to be passed at initialization' % self.__class__.__name__)

        instance = kwargs['instance']
        kwargs.setdefault('initial', {})
        kwargs['initial'].setdefault('body', instance.post.body)
        kwargs['initial'].setdefault('hidden', instance.post.hidden)
        kwargs['initial'].setdefault('close_topic', instance.post.topic.is_locked)

        super(InlineModeratePostReportForm, self).__init__(*args, **kwargs)

    def save(self, user, **kwargs):
        instance = super(InlineModeratePostReportForm, self).save(commit=False)

        instance.post.set_hidden(self.cleaned_data.get('hidden'))
        instance.post.body = self.cleaned_data.get('body')

        instance.moderator = user
        instance.status = 1 # Processed

        if self.cleaned_data.get('close_topic'):
            instance.post.topic.lock()
            instance.post.topic.save()

        instance.post.save()
        instance.save()

        return instance

    class Meta:
        model = PostReport
        fields = ('id', 'body', 'hidden', 'close_topic', 'moderator_comment',)


class ModeratePostReportForm(forms.ModelForm):
    #report_reason = forms.ChoiceField(label=_('Post reason'))

    class Meta(object):
        model = PostReport
        fields = ('moderator_comment', 'status')

    def __init__(self, *args, **kwargs):
        #Move args to kwargs
        if args:
            kwargs.update(dict(zip(inspect.getargspec(super(ModeratePostReportForm, self).__init__)[0][1:], args)))
        self.moderator = kwargs.pop('moderator', None)
        if not 'instance' in kwargs:
            raise ValueError('You should provide instance')

        #reason_choices = []
        #for row in PostReportReason.objects.values('id', 'title').all():
        #    reason_choices.append((row['id'], row['title']))
        #self.declared_fields['report_reason'].choices = reason_choices

        super(ModeratePostReportForm, self).__init__(**kwargs)

    def save(self, commit=True):
        post_report = super(ModeratePostReportForm, self).save(commit=False)
        if commit:
            post_report.save()
        return post_report


class MovePostForm(forms.Form):

    def __init__(self, instance, user, *args, **kwargs):
        super(MovePostForm, self).__init__(*args, **kwargs)
        self.instance = instance
        self.user = user
        self.post = self.instance
        self.category, self.forum, self.topic = self.post.get_parents()

        if not self.post.is_topic_head:
            # we do not move an entire topic but a part of it's posts. Let's select those posts.
            self.posts_to_move = Post.objects.filter(created__gte=self.post.created,
                                                     topic=self.topic).order_by('created', 'pk')
            # if multiple posts exists with the same created datetime, it's important to keep the
            # same order and do not move some posts which could be "before" our post.
            # We can not just filter by adding `pk__gt=self.post.pk` because we could exclude
            # some posts if for some reasons, a lesser pk has a greater "created" datetime
            # Most of the time, we just do one extra request to be sure the first post is
            # the wanted one
            first_pk = self.posts_to_move.values_list('pk', flat=True)[0]
            while first_pk != self.post.pk:
                self.posts_to_move = self.posts_to_move.exclude(pk=first_pk)
                first_pk = self.posts_to_move.values_list('pk', flat=True)[0]

            i = 0
            choices = []
            for post in self.posts_to_move[1:]:  # all except the current one
                i += 1
                bvars = {'author': util.get_pybb_profile(post.user).get_display_name(),
                         'abstract': Truncator(post.body_text).words(8),
                         'i': i}
                label = _('%(i)d (%(author)s: "%(abstract)s")') % bvars
                choices.append((i, label))
            choices.insert(0, (0, _('None')))
            choices.insert(0, (-1, _('All')))
            self.fields['number'] = forms.TypedChoiceField(
                label=ugettext_lazy('Number of following posts to move with'),
                choices=choices, required=True, coerce=int,
            )
            # we move the entire topic, so we want to change it's forum.
            # So, let's exclude the current one

        # get all forum where we can move this post (and the others)
        move_to_forums = permissions.perms.filter_forums(self.user, Forum.objects.all())
        if self.post.is_topic_head:
            # we move the entire topic, so we want to change it's forum.
            # So, let's exclude the current one
            move_to_forums = move_to_forums.exclude(pk=self.forum.pk)
        last_cat_pk = None
        choices = []
        for forum in move_to_forums.order_by('category__position', 'position', 'name'):
            if not permissions.perms.may_create_topic(self.user, forum):
                continue
            if last_cat_pk != forum.category.pk:
                last_cat_pk = forum.category.pk
                choices.append(('%s' % forum.category, []))
            if self.forum.pk == forum.pk:
                name = '%(forum)s (forum of the current post)' % {'forum': self.forum}
            else:
                name = '%s' % forum
            choices[-1][1].append((forum.pk, name))
        
        self.fields['move_to'] = forms.ChoiceField(label=ugettext_lazy('Move to forum'),
                                                   initial=self.forum.pk,
                                                   choices=choices, required=True,)
        self.fields['name'] = forms.CharField(label=_('New subject'),
                                              initial=self.topic.name,
                                              max_length=255, required=True)
        if permissions.perms.may_edit_topic_slug(self.user):
            self.fields['slug'] = forms.CharField(label=_('New topic slug'),
                                                  initial=self.topic.slug,
                                                  max_length=255, required=False)

    def get_new_topic(self):
        if hasattr(self, '_new_topic'):
            return self._new_topic
        if self.post.is_topic_head:
            topic = self.topic
        else:
            topic = Topic(user=self.post.user)

        if topic.name != self.cleaned_data['name']:
            topic.name = self.cleaned_data['name']
            # force slug auto-rebuild if slug is not speficied and topic is renamed
            topic.slug = self.cleaned_data.get('slug', None)
        elif self.cleaned_data.get('slug', None):
            topic.slug = self.cleaned_data['slug']

        topic.forum = Forum.objects.get(pk=self.cleaned_data['move_to'])
        topic.slug = create_or_check_slug(topic, Topic, forum=topic.forum)
        topic.save()
        return topic

    @method_decorator(compat.get_atomic_func())
    def save(self):
        data = self.cleaned_data
        topic = self.get_new_topic()

        if not self.post.is_topic_head:
            # we move some posts
            posts = self.posts_to_move
            if data['number'] != -1:
                number = data['number'] + 1  # we want to move at least the current post ;-)
                posts = posts[0:number]
            # update posts
            # we can not update with subqueries on same table with mysql 5.5
            # it raises: You can't specify target table 'pybb_post' for update in FROM clause
            # so we need to get all pks... It's bad for perfs, but posts are not often splited...
            posts_pks = [p.pk for p in posts]
            Post.objects.filter(pk__in=posts_pks).update(topic_id=topic.pk)

        topic.update_counters()
        topic.forum.update_counters()

        if topic.pk != self.topic.pk:
            # we just created a new topic. let's update the counters
            self.topic.update_counters()
        if self.forum.pk != topic.forum.pk:
            self.forum.update_counters()
        return Post.objects.get(pk=self.post.pk)


class AdminPostForm(PostForm):
    """
    Superusers can post messages from any user and from any time
    If no user with specified name - new user will be created
    """
    login = forms.CharField(label=ugettext_lazy('User'))

    def __init__(self, *args, **kwargs):
        if args:
            kwargs.update(dict(zip(inspect.getargspec(forms.ModelForm.__init__)[0][1:], args)))
        if 'instance' in kwargs and kwargs['instance']:
            kwargs.setdefault('initial', {}).update({'login': getattr(kwargs['instance'].user, username_field)})
        super(AdminPostForm, self).__init__(**kwargs)

    def save(self, *args, **kwargs):
        try:
            self.user = User.objects.filter(**{username_field: self.cleaned_data['login']}).get()
        except User.DoesNotExist:
            if username_field != 'email':
                create_data = {username_field: self.cleaned_data['login'],
                               'email': '%s@example.com' % self.cleaned_data['login'],
                               'is_staff': False}
            else:
                create_data = {'email': '%s@example.com' % self.cleaned_data['login'],
                               'is_staff': False}
            self.user = User.objects.create(**create_data)
        return super(AdminPostForm, self).save(*args, **kwargs)


try:
    class EditProfileForm(forms.ModelForm):
        class Meta(object):
            model = util.get_pybb_profile_model()
            fields = ['nickname', 'signature', 'time_zone', 'show_signatures', 'avatar']

        def __init__(self, *args, **kwargs):
            super(EditProfileForm, self).__init__(*args, **kwargs)
            self.fields['signature'].widget = forms.Textarea(attrs={'rows': 2, 'cols:': 60})

        def clean_avatar(self):
            if self.cleaned_data['avatar'] and (self.cleaned_data['avatar'].size > defaults.PYBB_MAX_AVATAR_SIZE):
                forms.ValidationError(ugettext('Avatar is too large, max size: %s bytes' %
                                               defaults.PYBB_MAX_AVATAR_SIZE))
            return self.cleaned_data['avatar']

        def clean_signature(self):
            value = self.cleaned_data['signature'].strip()
            if len(re.findall(r'\n', value)) > defaults.PYBB_SIGNATURE_MAX_LINES:
                raise forms.ValidationError('Number of lines is limited to %d' % defaults.PYBB_SIGNATURE_MAX_LINES)
            if len(value) > defaults.PYBB_SIGNATURE_MAX_LENGTH:
                raise forms.ValidationError('Length of signature is limited to %d' % defaults.PYBB_SIGNATURE_MAX_LENGTH)
            return value
except FieldError:
    pass


class UserSearchForm(forms.Form):
    query = forms.CharField(required=False, label='')

    def filter(self, qs):
        if self.is_valid():
            query = self.cleaned_data['query']
            return qs.filter(**{'%s__contains' % username_field: query})
        else:
            return qs


class PollForm(forms.Form):
    def __init__(self, topic, *args, **kwargs):
        self.topic = topic

        super(PollForm, self).__init__(*args, **kwargs)

        qs = PollAnswer.objects.filter(topic=topic)
        if topic.poll_type == Topic.POLL_TYPE_SINGLE:
            self.fields['answers'] = forms.ModelChoiceField(
                label='', queryset=qs, empty_label=None,
                widget=forms.RadioSelect())
        elif topic.poll_type == Topic.POLL_TYPE_MULTIPLE:
            self.fields['answers'] = forms.ModelMultipleChoiceField(
                label='', queryset=qs,
                widget=forms.CheckboxSelectMultiple())

    def clean_answers(self):
        answers = self.cleaned_data['answers']
        if self.topic.poll_type == Topic.POLL_TYPE_SINGLE:
            return [answers]
        else:
            return answers


class ForumSubscriptionForm(forms.Form):
    def __init__(self, user, forum, instance=None, *args, **kwargs):
        super(ForumSubscriptionForm, self).__init__(*args, **kwargs)
        self.user = user
        self.forum = forum
        self.instance = instance

        type_choices = list(ForumSubscription.TYPE_CHOICES)
        if instance :
            type_choices.append(
                ('unsubscribe', _('be unsubscribe from this forum')))
            type_initial = instance.type
        else:
            type_initial = ForumSubscription.TYPE_NOTIFY
        self.fields['type'] = forms.ChoiceField(
            label=_('You want to'), choices=type_choices, initial=type_initial,
            widget=forms.RadioSelect())

        topic_choices = (
            ('new', _('only new topics')),
            ('all', _('all topics of the forum')),
        )
        self.fields['topics'] = forms.ChoiceField(
            label=_('Concerned topics'), choices=topic_choices,
            initial=topic_choices[0][0], widget=forms.RadioSelect())

    def process(self):
        """
        saves or deletes the ForumSubscription's instance
        """
        action = self.cleaned_data.get('type')
        all_topics = self.cleaned_data.get('topics') == 'all'
        if action == 'unsubscribe':
            self.instance.delete(all_topics=all_topics)
            return 'delete-all' if all_topics else 'delete'
        else:
            if not self.instance:
                self.instance = ForumSubscription()
                self.instance.user = self.user
                self.instance.forum = self.forum
            self.instance.type = int(self.cleaned_data.get('type'))
            self.instance.save(all_topics=all_topics)
            return 'subscribe-all' if all_topics else 'subscribe'


class ModeratorForm(forms.Form):

    def __init__(self, user, *args, **kwargs):

        """
        Creates the form to grant moderator privileges, checking if the request user has the
        permission to do so.

        :param user: request user
        """

        super(ModeratorForm, self).__init__(*args, **kwargs)
        categories = Category.objects.all()
        self.authorized_forums = []
        if not permissions.perms.may_manage_moderators(user):
            raise PermissionDenied()
        for category in categories:
            forums = [forum.pk for forum in category.forums.all() if permissions.perms.may_change_forum(user, forum)]
            if forums:
                self.authorized_forums += forums
                self.fields['cat_%d' % category.pk] = forms.ModelMultipleChoiceField(
                    label=category.name,
                    queryset=category.forums.filter(pk__in=forums),
                    widget=forms.CheckboxSelectMultiple(),
                    required=False
                )

    def process(self, target_user):
        """
        Updates the target user moderator privilesges

        :param target_user: user to update
        """

        cleaned_forums = self.cleaned_data.values()
        initial_forum_set = target_user.forum_set.all()
        # concatenation of the lists into one
        checked_forums = [forum for queryset in cleaned_forums for forum in queryset]
        # keep all the forums, the request user does't have the permisssion to change
        untouchable_forums = [forum for forum in initial_forum_set if forum.pk not in self.authorized_forums]
        target_user.forum_set = checked_forums + untouchable_forums
