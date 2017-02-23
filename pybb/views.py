# -*- coding: utf-8 -*-

from __future__ import unicode_literals
import math
import json
from datetime import datetime, timedelta
from operator import itemgetter

from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.urlresolvers import reverse
from django.contrib import messages
from django.contrib.sites.shortcuts import get_current_site
from django.db.models import F, Count
from django.db.models.aggregates import Max
from django.forms.utils import ErrorList
from django.forms.models import inlineformset_factory
from django.http import HttpResponseRedirect, HttpResponse, Http404, HttpResponseBadRequest,\
    HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import ugettext as _
from django.utils.decorators import method_decorator
from django.views.decorators.http import require_POST
from django.views.generic.edit import ModelFormMixin
from django.views.decorators.csrf import csrf_protect
from django.views import generic
from django.conf import settings

from pybb import compat, defaults, util
from pybb.compat import get_atomic_func
from pybb.forms import PostForm, MovePostForm, AdminPostForm, AttachmentFormSet, \
    PollAnswerFormSet, PollForm, ForumSubscriptionForm, ModeratorForm, \
    EditProfileForm, TopicForm, MoveTopicForm, PostReportForm, SubscribeToTopicForm, \
    UnsubscribeFromTopicForm, ModeratePostReportForm, InlineModeratePostReportForm
from pybb.models import Category, Forum, ForumSubscription, Topic, Post, TopicReadTracker, \
    ForumReadTracker, PollAnswerUser, TopicViewTracker, PostReport, TopicTracker, \
    UserSetting
from pybb.permissions import *
from pybb.templatetags.pybb_tags import pybb_topic_poll_not_voted


User = compat.get_user_model()
username_field = compat.get_username_field()
Paginator, pure_pagination = compat.get_paginator_class()


class PostsListView(generic.ListView):
    """Sets posts per page size (:attr:`paginate_by`) based on the user's settings."""

    def dispatch(self, request, *args, **kwargs):
        # User must be logged in for custom settings
        if request.user.is_authenticated():
            self.paginate_by = \
                    UserSetting.get_setting_for_user(request.user,
                                                      'posts_per_page')

        return super(PostsListView, self).dispatch(request, *args, **kwargs)


class DeleteTopicView(generic.DeleteView):
    """View for deleting a Topic record. Requires administration permission for the relevant forum."""

    template_name = 'pybb/delete_topic.html'
    context_object_name = 'topic'

    def get_object(self, queryset=None):
        topic = get_object_or_404(Topic, pk=self.kwargs['pk'])
        self.forum = topic.forum
        if not topic.can_parent_forum_be_administered_by_user(self.request.user):
            raise PermissionDenied



        return topic

    def get_success_url(self):
        return self.forum.get_absolute_url()


class HideTopicView(generic.View):
    def post(self, *args, **kwargs):
        topic = get_object_or_404(Topic, pk=self.kwargs['pk'])
        if not pybb_can_administer_forum(self.request.user, topic.forum):
            raise PermissionDenied

        topic.hide()

        return HttpResponseRedirect(topic.get_absolute_url())


class UnhideTopicView(generic.View):
    def post(self, *args, **kwargs):
        topic = get_object_or_404(Topic, pk=self.kwargs['pk'])
        if not pybb_can_administer_forum(self.request.user, topic.forum):
            raise PermissionDenied

        topic.unhide()

        return HttpResponseRedirect(topic.get_absolute_url())


class AddTopicView(generic.CreateView):

    model = Topic
    form_class = TopicForm
    template_name = 'pybb/add_topic.html'

    def get_form_kwargs(self):
        forum = get_object_or_404(Forum, pk=self.kwargs['forum_id'])
        if not pybb_can_add_forum_topic(self.request.user, forum):
            raise PermissionDenied
        self.forum = forum

        ip = self.request.META.get('REMOTE_ADDR', '')
        self.preview = self.request.POST.has_key('preview')

        form_kwargs = super(AddTopicView, self).get_form_kwargs()
        form_kwargs.update(dict(forum=forum, user=self.user, preview=self.preview, ip=ip, initial={}))
        return form_kwargs

    def get_context_data(self, **kwargs):
        ctx = super(AddTopicView, self).get_context_data(**kwargs)
        ctx['forum'] = self.forum
        return ctx

    @method_decorator(csrf_protect)
    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated():
            self.user = request.user
        else:
            # Anonymous user
            self.user, new = User.objects.get_or_create(username=defaults.PYBB_ANONYMOUS_USERNAME)
        return super(AddTopicView, self).dispatch(request, *args, **kwargs)


class HideAllPostView(generic.View):
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated() or \
           not request.user.has_perm('pybb.change_pybbuser'):
            raise PermissionDenied

        return super(HideAllPostView, self).dispatch(request, *args, **kwargs)

    def get(self, *args, **kwargs):
        ids = self.request.GET.get('ids', '')
        if not ids:
            raise Http404('IDs parameter is empty')

        list_ids = ids.split(',')
        users = User.objects.filter(pk__in=list_ids).only('username')
        context = {
            'ids': ids,
            'users': users
        }
        return render(
            self.request,
            'pybb/hide_all_post.html',
            context
        )

    def post(self, *args, **kwargs):
        """User has submitted form, which acknowledges the action."""
        ids = self.request.POST.get('ids', None)
        if ids:
            list_ids = ids.split(',')
            Post.objects.filter(user__in=list_ids).update(hidden=True)
        return HttpResponseRedirect(reverse('admin:pybb_pybbuser_changelist'))


class MoveTopicView(generic.UpdateView):

    model = Topic
    form_class = MoveTopicForm
    context_object_name = 'topic'
    template_name = 'pybb/move_topic.html'

    def get_object(self, queryset=None):
        topic = super(MoveTopicView, self).get_object(queryset)
        if not pybb_can_administer_forum(self.request.user, topic.forum):
            raise PermissionDenied
        return topic

    def get_form_kwargs(self):
        ip = self.request.META.get('REMOTE_ADDR', '')
        site = get_current_site(self.request)
        form_kwargs = super(MoveTopicView, self).get_form_kwargs()
        form_kwargs.update(dict(user=self.request.user, ip=ip, initial={}, domain=site.domain))
        return form_kwargs


class SubscribeToTopicView(generic.UpdateView):

    model = Topic
    form_class = SubscribeToTopicForm
    context_object_name = 'topic'
    template_name = 'pybb/subscribe_to_topic.html'

    def get_form_kwargs(self):
        form_kwargs = super(SubscribeToTopicView, self).get_form_kwargs()
        form_kwargs.update(dict(user=self.request.user))
        return form_kwargs

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated():
            topic = get_object_or_404(Topic, pk=kwargs['pk'])
            if not pybb_can_view_forum(request.user, topic.forum):
                raise PermissionDenied
            self.user = request.user
        else:
            from django.contrib.auth.views import redirect_to_login
            if not request.is_ajax():
                return redirect_to_login(request.get_full_path())
            else:
                return HttpResponse(
                    json.dumps({ 'success': False, 'error': 'login_required' })
                )

        return super(SubscribeToTopicView, self).dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        # Most likely contains a HttpResponseRedirect
        result = super(SubscribeToTopicView, self).form_valid(form)

        if self.request.is_ajax():
            return HttpResponse(
                json.dumps({ 'success': True })
            )
        else:
            return result


class UnsubscribeFromTopicView(SubscribeToTopicView):

    form_class = UnsubscribeFromTopicForm
    template_name = 'pybb/unsubscribe_from_topic.html'


class ActiveTopicsView(generic.ListView):
    """Shows list of topics (single page) with the newest posts, filtered by
    forums that the current user has read access to.
    """

    paginate_by = defaults.PYBB_FORUM_PAGE_SIZE
    context_object_name = 'topic_list'
    template_name = 'pybb/active_topics.html'

    def get_queryset(self):
        visible_forums = pybb_get_visible_forums(self.request.user)

        return TopicTracker.objects.\
                filter(
                    topic__forum__in=visible_forums
                ).order_by('-last_visible_post').\
                select_related('topic')[:self.paginate_by]

    def get_context_data(self, **kwargs):
        ctx = super(ActiveTopicsView, self).get_context_data(**kwargs)
        ctx['maxpostid'] = Post.objects.aggregate(Max('id'))['id__max']
        return ctx


class SubscribedTopicsView(generic.ListView):

    paginate_by = defaults.PYBB_FORUM_PAGE_SIZE
    context_object_name = 'topic_list'
    template_name = 'pybb/subscribed_topics.html'
    paginator_class = Paginator

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super(SubscribedTopicsView, self).dispatch(request, *args, **kwargs)

    def get_queryset(self):
        list_topic_ids = Topic.objects.\
                filter(
                    subscribers=self.request.user
                ).values_list('pk', flat=True)

        return TopicTracker.objects.\
                filter(topic__pk__in=list_topic_ids).\
                order_by('-last_visible_post')

    def get_context_data(self, **kwargs):
        ctx = super(SubscribedTopicsView, self).get_context_data(**kwargs)
        return ctx


def active_topics_since(request):
    new_active_topic_count = 0

    maxpostid_str = request.GET.get("maxpostid", '')
    if maxpostid_str:
        try:
            maxpostid = int(maxpostid_str)
        except ValueError:
            pass
        else:
            visible_forums = pybb_get_visible_forums(request.user)
            new_active_topic_count = TopicTracker.objects.filter(last_visible_post__gt=maxpostid, topic__forum__in=visible_forums, topic__status=0).count()

    to_json = {"new_active_topic_count": new_active_topic_count}
    return HttpResponse(json.dumps(to_json), mimetype='application/json')


class HidePostView(generic.View):
    def post(self, *args, **kwargs):
        post = get_object_or_404(Post, pk=self.kwargs['pk'])
        if not pybb_can_administer_forum(self.request.user, post.topic.forum):
            raise PermissionDenied

        post.hide()

        return HttpResponseRedirect(post.get_absolute_url())


class UnhidePostView(generic.View):
    def post(self, *args, **kwargs):
        post = get_object_or_404(Post, pk=self.kwargs['pk'])
        if not pybb_can_administer_forum(self.request.user, post.topic.forum):
            raise PermissionDenied

        post.unhide()

        return HttpResponseRedirect(post.get_absolute_url())


class LockPostView(generic.View):
    def post(self, *args, **kwargs):
        post = get_object_or_404(Post, pk=self.kwargs['pk'])
        if not pybb_can_administer_forum(self.request.user, post.topic.forum):
            raise PermissionDenied
        post.status = 1
        post.save()
        return HttpResponseRedirect(post.get_absolute_url())


class UnlockPostView(generic.View):
    def post(self, *args, **kwargs):
        post = get_object_or_404(Post, pk=self.kwargs['pk'])
        if not pybb_can_administer_forum(self.request.user, post.topic.forum):
            raise PermissionDenied
        post.status = 0
        post.save()
        return HttpResponseRedirect(post.get_absolute_url())


class PostIpView(generic.TemplateView):
    template_name = 'pybb/post_ip.html'

    def get_context_data(self, **kwargs):
        post = get_object_or_404(Post, pk=self.kwargs['pk'])
        if not pybb_can_administer_forum(self.request.user, post.topic.forum):
            raise PermissionDenied

        ctx = super(PostIpView, self).get_context_data(**kwargs)
        ctx['post'] = post

        ctx['posts_from_ip_count'] = Post.objects.filter(user_ip=post.user_ip).count()

        posts_per_user_result = Post.objects.values('user').filter(user_ip=post.user_ip).annotate(num_posts=Count('user'))
        posts_per_user = []
        for item in posts_per_user_result:
            user = User.objects.get(pk=item['user'])
            posts_per_user.append({'user': user, 'post_count':item['num_posts']})
        ctx['posts_per_user'] = posts_per_user

        posts_from_ip_result = Post.objects.values('user_ip').filter(user=post.user).annotate(num_posts=Count('user_ip'))
        posts_from_ip = []
        for item in posts_from_ip_result:
            posts_from_ip.append({'ip': item['user_ip'], 'post_count':item['num_posts']})
        ctx['posts_from_ip'] = sorted(posts_from_ip, key=itemgetter('post_count'), reverse=True)

        return ctx


class AddPostReportView(generic.CreateView):

    model = PostReport
    form_class = PostReportForm
    context_object_name = 'reported_post'
    template_name = 'pybb/add_post_report.html'

    def get_form_kwargs(self):
        self.post = get_object_or_404(Post, pk=self.kwargs['pk'])
        if not self.request.user.is_authenticated():
            raise PermissionDenied
        if not pybb_can_view_forum(self.request.user, self.post.topic.forum):
            raise PermissionDenied
        form_kwargs = super(AddPostReportView, self).get_form_kwargs()
        form_kwargs.update(dict(reporter=self.request.user, post=self.post, initial={}))
        return form_kwargs

    def get_context_data(self, **kwargs):
        ctx = super(AddPostReportView, self).get_context_data(**kwargs)
        ctx['post'] = self.post
        return ctx

    def form_valid(self, *args, **kwargs):
        messages.add_message(self.request, messages.SUCCESS, _('Your report has been submitted'))
        return super(AddPostReportView, self).form_valid(*args, **kwargs)

    def get_success_url(self):
        return self.post.topic.get_absolute_url()


class PostReportListView(generic.ListView):

    model = PostReport
    template_name = 'pybb/post_report_list.html'
    context_object_name = 'report_list'
    paginate_by = defaults.PYBB_FORUM_PAGE_SIZE
    paginator_class = Paginator
    form_class = InlineModeratePostReportForm

    def dispatch(self, request, *args, **kwargs):
        # Only users, which have permissions to administer at least one forum, can view this page
        administrated_forums = pybb_get_forums_with_perm(request.user, "administer_forum")
        if not administrated_forums:
            raise PermissionDenied

        return super(PostReportListView, self).dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        """Handles moderation form."""
        try:
            post_report = PostReport.objects.get(pk=int(request.POST.get('id')))
        except (TypeError, KeyError, PostReport.DoesNotExist), e:
            raise Http404(e)

        form_kwargs = self.get_instance_form_kwargs(post_report)
        form_kwargs['data'] = request.POST
        form = self.form_class(**form_kwargs)
        form.save(user=self.request.user)

        return HttpResponseRedirect(request.get_full_path())

    def get_queryset(self):
        self.unprocessed = self.kwargs.has_key('unprocessed')
        return PostReport.get_post_reports_for_user(self.request.user, not self.unprocessed)

    def get_instance_form_kwargs(self, post_report):
        """These kwargs are used to initialize the 'post report moderate' form
        for each report in the list.
        """
        form_kwargs = {
            'instance': post_report,
        }
        return form_kwargs

    def get_context_data(self, **kwargs):
        ctx = super(PostReportListView, self).get_context_data(**kwargs)
        ctx['unprocessed'] = self.unprocessed

        for post_report in ctx.get(self.context_object_name):
            post_report.form = \
                self.form_class(**self.get_instance_form_kwargs(post_report))

        return ctx


class PostReportView(generic.RedirectView):
    # Trampoline to get to the right page on the post report list
    def get_redirect_url(self, **kwargs):
        post_report = get_object_or_404(PostReport, pk=self.kwargs['pk'])
        count = PostReport.objects.filter(id__gt=post_report.id).count() + 1
        page = math.ceil(count / float(PostReportListView.paginate_by))
        return '%s?page=%d#post-report-%d' % (reverse('pybb:post_report_list'), page, post_report.id)


class ModeratePostReportView(generic.UpdateView):
    model = PostReport
    form_class = ModeratePostReportForm
    template_name = 'pybb/moderate_post_report.html'
    context_object_name = 'report'

    def get_object(self, queryset=None):
        self.post_report = get_object_or_404(PostReport, pk=self.kwargs['pk'])
        if not pybb_can_administer_forum(self.request.user, self.post_report.post.topic.forum):
            raise PermissionDenied
        return self.post_report

    def get_form_kwargs(self):
        form_kwargs = super(ModeratePostReportView, self).get_form_kwargs()
        form_kwargs.update(dict(moderator=self.request.user, initial={}))
        return form_kwargs

    def get_success_url(self):
        return self.post_report.get_absolute_url()


class TopicFirstUnreadPostView(generic.RedirectView):
    """Redirects the user to the first unread Post since his last visit to the
    topic, or the last post if required data is unavailable.
    """
    permanent = False

    def get_redirect_url(self, **kwargs):
        url = None
        topic = get_object_or_404(Topic, pk=self.kwargs['pk'])

        # Try to lookup the last viewed post by the user
        last_read_post = topic.get_last_post_viewed_by_user(self.request.user)

        if last_read_post:
            # Get the next post
            try:
                first_unread_post = Post.objects.filter(
                    topic=topic,
                    pk__gt=last_read_post.pk
                )[0]
                # Redirect to page number the post is on, and use its ID as the
                # anchor
                page_number = first_unread_post.page_number

                if page_number:
                    url = reverse(
                        'pybb:topic',
                        kwargs={
                            'pk': topic.pk,
                            'page': page_number
                        }
                    ) + '#post-%d' % first_unread_post.pk
            except IndexError:
                # Will be catched by next if
                pass

        if not url:
            # Some data is missing. Redirect to the last post in the topic
            url = topic.get_last_page_url()

        return url


class PaginatorMixin(object):
    def get_paginator(self, queryset, per_page, orphans=0, allow_empty_first_page=True, **kwargs):
        kwargs = {}
        if pure_pagination:
            kwargs['request'] = self.request
        return Paginator(queryset, per_page, orphans=0, allow_empty_first_page=True, **kwargs)


class RedirectToLoginMixin(object):
    """ mixin which redirects to settings.LOGIN_URL if the view encounters an PermissionDenied exception
        and the user is not authenticated. Views inheriting from this need to implement
        get_login_redirect_url(), which returns the URL to redirect to after login (parameter "next")
    """
    def dispatch(self, request, *args, **kwargs):
        try:
            return super(RedirectToLoginMixin, self).dispatch(request, *args, **kwargs)
        except PermissionDenied:
            if not request.user.is_authenticated():
                from django.contrib.auth.views import redirect_to_login
                return redirect_to_login(self.get_login_redirect_url())
            else:
                return HttpResponseForbidden()

    def get_login_redirect_url(self):
        """ get the url to which we redirect after the user logs in. subclasses should override this """
        return '/'


class IndexView(generic.ListView):

    model = Category
    template_name = 'pybb/index.html'
    context_object_name = 'categories'

    def get_context_data(self, **kwargs):
        ctx = super(IndexView, self).get_context_data(**kwargs)
        categories = ctx['categories']
        for category in categories:
            category.forums_accessed = perms.filter_forums(self.request.user, category.forums.filter(parent=None))
        ctx['categories'] = categories
        return ctx

    def get_queryset(self):
        return perms.filter_categories(self.request.user, Category.objects.all())


class CategoryView(RedirectToLoginMixin, generic.DetailView):

    template_name = 'pybb/index.html'
    context_object_name = 'category'

    def get_login_redirect_url(self):
        # returns super.get_object as there is a conflict with the perms in CategoryView.get_object
        # Would raise a PermissionDenied and never redirect
        return super(CategoryView, self).get_object().get_absolute_url()

    def get_queryset(self):
        return Category.objects.all()

    def get_object(self, queryset=None):
        obj = super(CategoryView, self).get_object(queryset)
        if not perms.may_view_category(self.request.user, obj):
            raise PermissionDenied
        return obj

    def get_context_data(self, **kwargs):
        ctx = super(CategoryView, self).get_context_data(**kwargs)
        ctx['category'].forums_accessed = perms.filter_forums(self.request.user, ctx['category'].forums.filter(parent=None))
        ctx['categories'] = [ctx['category']]
        return ctx

    def get(self, *args, **kwargs):
        if defaults.PYBB_NICE_URL and (('id' in kwargs) or ('pk' in kwargs)):
            return redirect(super(CategoryView, self).get_object(), permanent=defaults.PYBB_NICE_URL_PERMANENT_REDIRECT)
        return super(CategoryView, self).get(*args, **kwargs)


class ForumView(RedirectToLoginMixin, PaginatorMixin, generic.ListView):

    paginate_by = defaults.PYBB_FORUM_PAGE_SIZE
    context_object_name = 'topic_list'
    template_name = 'pybb/forum.html'

    def dispatch(self, request, *args, **kwargs):
        self.forum = self.get_forum(**kwargs)
        return super(ForumView, self).dispatch(request, *args, **kwargs)

    def get_login_redirect_url(self):
        return self.forum.get_absolute_url()

    def get_context_data(self, **kwargs):
        ctx = super(ForumView, self).get_context_data(**kwargs)
        ctx['forum'] = self.forum
        if self.request.user.is_authenticated():
            try:
                ctx['subscription'] = ForumSubscription.objects.get(
                    user=self.request.user,
                    forum=self.forum
                )
            except ForumSubscription.DoesNotExist:
                ctx['subscription'] = None
        else:
            ctx['subscription'] = None
        ctx['forum'].forums_accessed = perms.filter_forums(self.request.user, self.forum.child_forums.all())
        return ctx

    def get_queryset(self):
        if not perms.may_view_forum(self.request.user, self.forum):
            raise PermissionDenied

        qs = self.forum.topics.order_by('-sticky', '-updated', '-id').select_related()
        qs = perms.filter_topics(self.request.user, qs)
        return qs

    def get_forum(self, **kwargs):
        if 'pk' in kwargs:
            forum = get_object_or_404(Forum.objects.all(), pk=kwargs['pk'])
        elif ('slug' and 'category_slug') in kwargs:
            forum = get_object_or_404(Forum, slug=kwargs['slug'], category__slug=kwargs['category_slug'])
        else:
            raise Http404(_('Forum does not exist'))
        return forum

    def get(self, *args, **kwargs):
        if defaults.PYBB_NICE_URL and 'pk' in kwargs:
            return redirect(self.forum, permanent=defaults.PYBB_NICE_URL_PERMANENT_REDIRECT)
        return super(ForumView, self).get(*args, **kwargs)


class ForumSubscriptionView(RedirectToLoginMixin, generic.FormView):
    template_name = 'pybb/forum_subscription.html'
    form_class = ForumSubscriptionForm

    def get_login_redirect_url(self):
        return reverse('pybb:forum_subscription', args=(self.kwargs['pk'],))

    def get_success_url(self):
        return self.forum.get_absolute_url()

    def get_form_kwargs(self):
        kw = super(ForumSubscriptionView, self).get_form_kwargs()
        self.get_objects()
        kw['instance'] = self.forum_subscription
        kw['user'] = self.request.user
        kw['forum'] = self.forum
        return kw

    def get_context_data(self, **kwargs):
        ctx = super(ForumSubscriptionView, self).get_context_data(**kwargs)
        ctx['forum'] = self.forum
        ctx['forum_subscription'] = self.forum_subscription
        return ctx

    def form_valid(self, form):
        result = form.process()
        if result == 'subscribe-all':
            msg = _((
                'You subscribed to all existant topics on this forum '
                'and you will auto-subscribed to all its new topics.'
            ))
        elif result == 'delete':
            msg = _((
                'You won\'t be notified anymore each time a new topic '
                'is posted on this forum.'
            ))
        elif result == 'delete-all':
            msg = _((
                'You have been subscribed to all current topics in this forum and you won\'t'
                'be auto-subscribed anymore for each new topic posted on this forum.'
            ))
        else:
            msg = _((
                'You will be notified each time a new topic is posted on this forum.'
            ))
        messages.success(self.request, msg, fail_silently=True)
        return super(ForumSubscriptionView, self).form_valid(form)

    def get_objects(self):
        if not self.request.user.is_authenticated():
            raise PermissionDenied
        self.forum = get_object_or_404(Forum.objects.all(), pk=self.kwargs['pk'])
        try:
            self.forum_subscription = ForumSubscription.objects.get(
                user=self.request.user,
                forum=self.forum
            )
        except ForumSubscription.DoesNotExist:
            self.forum_subscription = None

class LatestTopicsView(PaginatorMixin, generic.ListView):

    paginate_by = defaults.PYBB_FORUM_PAGE_SIZE
    context_object_name = 'topic_list'
    template_name = 'pybb/latest_topics.html'

    def get_queryset(self):
        qs = Topic.objects.all().select_related()
        qs = perms.filter_topics(self.request.user, qs)
        return qs.order_by('-updated', '-id')


class PybbFormsMixin(object):

    post_form_class = PostForm
    admin_post_form_class = AdminPostForm
    attachment_formset_class = AttachmentFormSet
    poll_form_class = PollForm
    poll_answer_formset_class = PollAnswerFormSet

    def get_post_form_class(self):
        return self.post_form_class

    def get_admin_post_form_class(self):
        return self.admin_post_form_class

    def get_attachment_formset_class(self):
        return self.attachment_formset_class

    def get_poll_form_class(self):
        return self.poll_form_class

    def get_poll_answer_formset_class(self):
        return self.poll_answer_formset_class


class TopicView(RedirectToLoginMixin, PaginatorMixin, PybbFormsMixin, generic.ListView):
    paginate_by = defaults.PYBB_TOPIC_PAGE_SIZE
    template_object_name = 'post_list'
    template_name = 'pybb/topic.html'

    def get(self, request, *args, **kwargs):
        if defaults.PYBB_NICE_URL and 'pk' in kwargs:
            return redirect(self.topic, permanent=defaults.PYBB_NICE_URL_PERMANENT_REDIRECT)
        response = super(TopicView, self).get(request, *args, **kwargs)
        self.mark_read()
        return response

    def get_login_redirect_url(self):
        return self.topic.get_absolute_url()

    @method_decorator(csrf_protect)
    def dispatch(self, request, *args, **kwargs):
        self.topic = self.get_topic(**kwargs)

        if request.GET.get('first-unread'):
            if request.user.is_authenticated():
                read_dates = []
                try:
                    read_dates.append(TopicReadTracker.objects.get(user=request.user, topic=self.topic).time_stamp)
                except TopicReadTracker.DoesNotExist:
                    pass
                try:
                    read_dates.append(ForumReadTracker.objects.get(user=request.user, forum=self.topic.forum).time_stamp)
                except ForumReadTracker.DoesNotExist:
                    pass

                read_date = read_dates and max(read_dates)
                if read_date:
                    try:
                        first_unread_topic = self.topic.posts.filter(created__gt=read_date).order_by('created', 'id')[0]
                    except IndexError:
                        first_unread_topic = self.topic.last_post
                else:
                    first_unread_topic = self.topic.head
                return HttpResponseRedirect(reverse('pybb:post', kwargs={'pk': first_unread_topic.id}))

        return super(TopicView, self).dispatch(request, *args, **kwargs)

    def get_queryset(self):
        if not perms.may_view_topic(self.request.user, self.topic):
            raise PermissionDenied
        if self.request.user.is_authenticated() or not defaults.PYBB_ANONYMOUS_VIEWS_CACHE_BUFFER:
            Topic.objects.filter(id=self.topic.id).update(views=F('views') + 1)
        else:
            cache_key = util.build_cache_key('anonymous_topic_views', topic_id=self.topic.id)
            cache.add(cache_key, 0)
            if cache.incr(cache_key) % defaults.PYBB_ANONYMOUS_VIEWS_CACHE_BUFFER == 0:
                Topic.objects.filter(id=self.topic.id).update(views=F('views') +
                                                                defaults.PYBB_ANONYMOUS_VIEWS_CACHE_BUFFER)
                cache.set(cache_key, 0)
        qs = self.topic.posts.all().select_related('user')
        if defaults.PYBB_PROFILE_RELATED_NAME:
            qs = qs.select_related('user__%s' % defaults.PYBB_PROFILE_RELATED_NAME)
        if not perms.may_moderate_topic(self.request.user, self.topic):
            qs = perms.filter_posts(self.request.user, qs)
        return qs

    def get_context_data(self, **kwargs):
        ctx = super(TopicView, self).get_context_data(**kwargs)

        if self.request.user.is_authenticated():
            self.request.user.is_moderator = perms.may_moderate_topic(self.request.user, self.topic)
            self.request.user.is_subscribed = self.request.user in self.topic.subscribers.all()
            if defaults.PYBB_ENABLE_ADMIN_POST_FORM and \
                    perms.may_post_as_admin(self.request.user):
                ctx['form'] = self.get_admin_post_form_class()(
                    initial={'login': getattr(self.request.user, username_field)},
                    topic=self.topic)
            else:
                ctx['form'] = self.get_post_form_class()(topic=self.topic)
        elif defaults.PYBB_ENABLE_ANONYMOUS_POST:
            ctx['form'] = self.get_post_form_class()(topic=self.topic)
        else:
            ctx['form'] = None
            ctx['next'] = self.get_login_redirect_url()
        if perms.may_attach_files(self.request.user):
            aformset = self.get_attachment_formset_class()()
            ctx['aformset'] = aformset
            ctx['attachment_max_size'] = defaults.PYBB_ATTACHMENT_SIZE_LIMIT
        if defaults.PYBB_FREEZE_FIRST_POST:
            ctx['first_post'] = self.topic.head
        else:
            ctx['first_post'] = None
        ctx['topic'] = self.topic

        if perms.may_vote_in_topic(self.request.user, self.topic) and \
                pybb_topic_poll_not_voted(self.topic, self.request.user):
            ctx['poll_form'] = self.get_poll_form_class()(self.topic)

        return ctx

    @method_decorator(get_atomic_func())
    def mark_read(self):
        if not self.request.user.is_authenticated():
            return
        try:
            forum_mark = ForumReadTracker.objects.get(forum=self.topic.forum, user=self.request.user)
        except ForumReadTracker.DoesNotExist:
            forum_mark = None
        if (forum_mark is None) or (forum_mark.time_stamp < self.topic.updated):
            topic_mark, new = TopicReadTracker.objects.get_or_create_tracker(topic=self.topic, user=self.request.user)
            if not new and topic_mark.time_stamp > self.topic.updated:
                # Bail early if we already read this thread.
                return

            # Check, if there are any unread topics in forum
            readed_trackers = TopicReadTracker.objects.filter(
                user=self.request.user, topic__forum=self.topic.forum, time_stamp__gte=F('topic__updated'))
            unread = self.topic.forum.topics.exclude(topicreadtracker__in=readed_trackers)
            if forum_mark is not None:
                unread = unread.filter(updated__gte=forum_mark.time_stamp)

            if not unread.exists():
                # Clear all topic marks for this forum, mark forum as read
                TopicReadTracker.objects.filter(user=self.request.user, topic__forum=self.topic.forum).delete()
                forum_mark, new = ForumReadTracker.objects.get_or_create_tracker(
                    forum=self.topic.forum, user=self.request.user)
                forum_mark.save()

    def get_topic(self, **kwargs):
        if 'pk' in kwargs:
            topic = get_object_or_404(Topic, pk=kwargs['pk'], post_count__gt=0)
        elif ('slug'and 'forum_slug'and 'category_slug') in kwargs:
            topic = get_object_or_404(
                Topic,
                slug=kwargs['slug'],
                forum__slug=kwargs['forum_slug'],
                forum__category__slug=kwargs['category_slug'],
                post_count__gt=0
                )
        else:
            raise Http404(_('This topic does not exists'))
        return topic


class PostEditMixin(PybbFormsMixin):

    @method_decorator(get_atomic_func())
    def post(self, request, *args, **kwargs):
        return super(PostEditMixin, self).post(request, *args, **kwargs)

    def get_form_class(self):
        if defaults.PYBB_ENABLE_ADMIN_POST_FORM and \
                perms.may_post_as_admin(self.request.user):
            return self.get_admin_post_form_class()
        else:
            return self.get_post_form_class()

    def get_context_data(self, **kwargs):

        ctx = super(PostEditMixin, self).get_context_data(**kwargs)

        if perms.may_attach_files(self.request.user) and 'aformset' not in kwargs:
            ctx['aformset'] = self.get_attachment_formset_class()(
                instance=getattr(self, 'object', None)
            )

        if perms.may_create_poll(self.request.user) and 'pollformset' not in kwargs:
            ctx['pollformset'] = self.get_poll_answer_formset_class()(
                instance=self.object.topic if getattr(self, 'object', None) else None
            )

        return ctx

    def form_valid(self, form):
        success = True
        save_attachments = False
        save_poll_answers = False
        self.object, topic = form.save(commit=False)

        if perms.may_attach_files(self.request.user):
            aformset = self.get_attachment_formset_class()(
                self.request.POST, self.request.FILES, instance=self.object
            )
            if aformset.is_valid():
                save_attachments = True
            else:
                success = False
        else:
            aformset = None

        if perms.may_create_poll(self.request.user):
            pollformset = self.get_poll_answer_formset_class()()
            if getattr(self, 'forum', None) or topic.head == self.object:
                if topic.poll_type != Topic.POLL_TYPE_NONE:
                    pollformset = self.get_poll_answer_formset_class()(
                        self.request.POST, instance=topic
                    )
                    if pollformset.is_valid():
                        save_poll_answers = True
                    else:
                        success = False
                else:
                    topic.poll_question = None
                    topic.poll_answers.all().delete()
        else:
            pollformset = None

        if success:
            try:
                topic.save()
            except ValidationError as e:
                success = False
                errors = form._errors.setdefault('name', ErrorList())
                errors += e.error_list
            else:
                self.object.topic = topic
                self.object.save()
                if save_attachments:
                    aformset.save()
                    if self.object.attachments.count():
                        # re-parse the body to replace attachment's references by URLs
                        self.object.save()
                if save_poll_answers:
                    pollformset.save()
                return HttpResponseRedirect(self.get_success_url())
        return self.render_to_response(self.get_context_data(form=form,
                                                             aformset=aformset,
                                                             pollformset=pollformset))


class AddPostView(PostEditMixin, generic.CreateView):

    template_name = 'pybb/add_post.html'

    @method_decorator(csrf_protect)
    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated():
            self.user = request.user
        else:
            if defaults.PYBB_ENABLE_ANONYMOUS_POST:
                self.user, new = User.objects.get_or_create(**{username_field: defaults.PYBB_ANONYMOUS_USERNAME})
            else:
                from django.contrib.auth.views import redirect_to_login
                return redirect_to_login(request.get_full_path())

        self.forum = None
        self.topic = None
        if 'forum_id' in kwargs:
            self.forum = get_object_or_404(perms.filter_forums(request.user, Forum.objects.all()), pk=kwargs['forum_id'])
            if not perms.may_create_topic(self.user, self.forum):
                raise PermissionDenied
        elif 'topic_id' in kwargs:
            self.topic = get_object_or_404(perms.filter_topics(request.user, Topic.objects.all()), pk=kwargs['topic_id'])
            if not perms.may_create_post(self.user, self.topic):
                raise PermissionDenied

            self.quote = ''
            if 'quote_id' in request.GET:
                try:
                    quote_id = int(request.GET.get('quote_id'))
                except TypeError:
                    raise Http404
                else:
                    post = get_object_or_404(Post, pk=quote_id)
                    if not perms.may_view_post(request.user, post):
                        raise PermissionDenied
                    profile = util.get_pybb_profile(post.user)
                    self.quote = util._get_markup_quoter(defaults.PYBB_MARKUP)(post.body, profile.get_display_name())

                if self.quote and request.is_ajax():
                    return HttpResponse(self.quote)
        return super(AddPostView, self).dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        ip = self.request.META.get('REMOTE_ADDR', '')
        form_kwargs = super(AddPostView, self).get_form_kwargs()
        form_kwargs.update(dict(topic=self.topic, forum=self.forum, user=self.user,
                           ip=ip, initial={}))
        if getattr(self, 'quote', None):
            form_kwargs['initial']['body'] = self.quote
        if defaults.PYBB_ENABLE_ADMIN_POST_FORM and \
                perms.may_post_as_admin(self.user):
            form_kwargs['initial']['login'] = getattr(self.user, username_field)
        form_kwargs['may_create_poll'] = perms.may_create_poll(self.user)
        form_kwargs['may_edit_topic_slug'] = perms.may_edit_topic_slug(self.user)
        return form_kwargs

    def get_context_data(self, **kwargs):
        ctx = super(AddPostView, self).get_context_data(**kwargs)
        ctx['forum'] = self.forum
        ctx['topic'] = self.topic
        return ctx

    def get_success_url(self):
        if (not self.request.user.is_authenticated()) and defaults.PYBB_PREMODERATION:
            return reverse('pybb:index')
        return self.object.get_absolute_url()


class EditPostView(PostEditMixin, generic.UpdateView):

    model = Post

    context_object_name = 'post'
    template_name = 'pybb/edit_post.html'

    @method_decorator(login_required)
    @method_decorator(csrf_protect)
    def dispatch(self, request, *args, **kwargs):
        return super(EditPostView, self).dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        form_kwargs = super(EditPostView, self).get_form_kwargs()
        form_kwargs['may_create_poll'] = perms.may_create_poll(self.request.user)
        return form_kwargs

    def get_object(self, queryset=None):
        post = super(EditPostView, self).get_object(queryset)
        if not perms.may_edit_post(self.request.user, post):
            raise PermissionDenied
        return post


class MovePostView(RedirectToLoginMixin, generic.UpdateView):

    model = Post
    form_class = MovePostForm
    context_object_name = 'post'
    template_name = 'pybb/move_post.html'

    @method_decorator(login_required)
    @method_decorator(csrf_protect)
    def dispatch(self, request, *args, **kwargs):
        return super(MovePostView, self).dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        form_kwargs = super(MovePostView, self).get_form_kwargs()
        form_kwargs['user'] = self.request.user
        return form_kwargs

    def get_object(self, queryset=None):
        post = super(MovePostView, self).get_object(queryset)
        if not perms.may_moderate_topic(self.request.user, post.topic):
            raise PermissionDenied
        return post

    def form_valid(self, *args, **kwargs):
        from django.db.models.signals import post_save
        from pybb.signals import topic_saved
        # FIXME: we should have specific signals to send notifications to topic/forum subscribers
        # but for now, we must connect / disconnect the callback
        post_save.disconnect(topic_saved, sender=Topic)
        response = super(MovePostView, self).form_valid(*args, **kwargs)
        post_save.connect(topic_saved, sender=Topic)
        return response

    def get_success_url(self):
        return self.object.topic.get_absolute_url()


class UserView(generic.DetailView):
    model = User
    template_name = 'pybb/user.html'
    context_object_name = 'target_user'

    def get_object(self, queryset=None):
        if queryset is None:
            queryset = self.get_queryset()
        return get_object_or_404(queryset, **{username_field: self.kwargs['username']})

    def get_context_data(self, **kwargs):
        ctx = super(UserView, self).get_context_data(**kwargs)
        ctx['topic_count'] = Topic.objects.filter(user=ctx['target_user']).count()
        return ctx


class UserPosts(PaginatorMixin, generic.ListView):
    model = Post
    paginate_by = defaults.PYBB_TOPIC_PAGE_SIZE
    template_name = 'pybb/user_posts.html'

    def dispatch(self, request, *args, **kwargs):
        username = kwargs.pop('username')
        self.user = get_object_or_404(**{'klass': User, username_field: username})
        return super(UserPosts, self).dispatch(request, *args, **kwargs)

    def get_queryset(self):
        qs = super(UserPosts, self).get_queryset()
        qs = qs.filter(user=self.user)
        qs = perms.filter_posts(self.request.user, qs).select_related('topic')
        qs = qs.order_by('-created', '-updated', '-id')
        return qs

    def get_context_data(self, **kwargs):
        context = super(UserPosts, self).get_context_data(**kwargs)
        context['target_user'] = self.user
        return context


class UserTopics(PaginatorMixin, generic.ListView):
    model = Topic
    paginate_by = defaults.PYBB_FORUM_PAGE_SIZE
    template_name = 'pybb/user_topics.html'

    def dispatch(self, request, *args, **kwargs):
        username = kwargs.pop('username')
        self.user = get_object_or_404(**{'klass': User, username_field: username})
        return super(UserTopics, self).dispatch(request, *args, **kwargs)

    def get_queryset(self):
        qs = super(UserTopics, self).get_queryset()
        qs = qs.filter(user=self.user)
        qs = perms.filter_topics(self.request.user, qs)
        qs = qs.order_by('-updated', '-created', '-id')
        return qs

    def get_context_data(self, **kwargs):
        context = super(UserTopics, self).get_context_data(**kwargs)
        context['target_user'] = self.user
        return context


class PostView(RedirectToLoginMixin, generic.RedirectView):

    permanent = False

    def dispatch(self, request, *args, **kwargs):
        self.post = self.get_post(**kwargs)
        return super(PostView, self).dispatch(request, *args, **kwargs)

    def get_login_redirect_url(self):
        return self.post.get_absolute_url()

    def get_redirect_url(self, **kwargs):
        if not perms.may_view_post(self.request.user, self.post):
            raise PermissionDenied
        count = self.post.topic.posts.filter(created__lt=self.post.created).count() + 1
        page = math.ceil(count / float(defaults.PYBB_TOPIC_PAGE_SIZE))
        return '%s?page=%d#post-%d' % (self.post.topic.get_absolute_url(), page, self.post.id)

    def get_post(self, **kwargs):
        return get_object_or_404(Post, pk=kwargs['pk'])


class ModeratePost(generic.RedirectView):

    permanent = False

    def get_redirect_url(self, **kwargs):
        post = get_object_or_404(Post, pk=self.kwargs['pk'])
        if not perms.may_moderate_topic(self.request.user, post.topic):
            raise PermissionDenied
        post.on_moderation = False
        post.save()
        return post.get_absolute_url()


class ProfileEditView(generic.UpdateView):

    template_name = 'pybb/edit_profile.html'

    def get_object(self, queryset=None):
        return util.get_pybb_profile(self.request.user)

    def get_form_class(self):
        if not self.form_class:
            from pybb.forms import EditProfileForm
            return EditProfileForm
        else:
            return super(ProfileEditView, self).get_form_class()

    @method_decorator(login_required)
    @method_decorator(csrf_protect)
    def dispatch(self, request, *args, **kwargs):
        return super(ProfileEditView, self).dispatch(request, *args, **kwargs)

    def get_success_url(self):
        return reverse('pybb:edit_profile')


class DeletePostView(generic.DeleteView):

    template_name = 'pybb/delete_post.html'
    context_object_name = 'post'

    def get_object(self, queryset=None):
        post = get_object_or_404(Post.objects.select_related('topic', 'topic__forum'), pk=self.kwargs['pk'])
        if not perms.may_delete_post(self.request.user, post):
            raise PermissionDenied
        self.topic = post.topic
        self.forum = post.topic.forum
        return post

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        self.object.delete()
        redirect_url = self.get_success_url()
        if not request.is_ajax():
            return HttpResponseRedirect(redirect_url)
        else:
            return HttpResponse(redirect_url)

    def get_success_url(self):
        try:
            Topic.objects.get(pk=self.topic.id)
        except Topic.DoesNotExist:
            return self.forum.get_absolute_url()
        else:
            if not self.request.is_ajax():
                return self.topic.get_absolute_url()
            else:
                return ""


class TopicActionBaseView(generic.View):

    def get_topic(self):
        return get_object_or_404(Topic, pk=self.kwargs['pk'])

    @method_decorator(login_required)
    def get(self, *args, **kwargs):
        self.topic = self.get_topic()
        self.action(self.topic)
        return HttpResponseRedirect(self.topic.get_absolute_url())


class StickTopicView(TopicActionBaseView):

    def action(self, topic):
        if not perms.may_stick_topic(self.request.user, topic):
            raise PermissionDenied
        topic.sticky = True
        topic.save()


class UnstickTopicView(TopicActionBaseView):

    def action(self, topic):
        if not perms.may_unstick_topic(self.request.user, topic):
            raise PermissionDenied
        topic.sticky = False
        topic.save()


class CloseTopicView(TopicActionBaseView):

    def action(self, topic):
        if not perms.may_close_topic(self.request.user, topic):
            raise PermissionDenied
        topic.closed = True
        topic.save()


class OpenTopicView(TopicActionBaseView):
    def action(self, topic):
        if not perms.may_open_topic(self.request.user, topic):
            raise PermissionDenied
        topic.closed = False
        topic.save()


class TopicPollVoteView(PybbFormsMixin, generic.UpdateView):
    model = Topic
    http_method_names = ['post', ]

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super(TopicPollVoteView, self).dispatch(request, *args, **kwargs)

    def get_form_class(self):
        return self.get_poll_form_class()

    def get_form_kwargs(self):
        kwargs = super(ModelFormMixin, self).get_form_kwargs()
        kwargs['topic'] = self.object
        return kwargs

    def form_valid(self, form):
        # already voted
        if not perms.may_vote_in_topic(self.request.user, self.object) or \
           not pybb_topic_poll_not_voted(self.object, self.request.user):
            return HttpResponseForbidden()

        answers = form.cleaned_data['answers']
        for answer in answers:
            # poll answer from another topic
            if answer.topic != self.object:
                return HttpResponseBadRequest()

            PollAnswerUser.objects.create(poll_answer=answer, user=self.request.user)
        return super(ModelFormMixin, self).form_valid(form)

    def form_invalid(self, form):
        return redirect(self.object)

    def get_success_url(self):
        return self.object.get_absolute_url()


@login_required
def topic_cancel_poll_vote(request, pk):
    topic = get_object_or_404(Topic, pk=pk)
    PollAnswerUser.objects.filter(user=request.user, poll_answer__topic_id=topic.id).delete()
    return HttpResponseRedirect(topic.get_absolute_url())


@login_required
def delete_subscription(request, topic_id):
    topic = get_object_or_404(perms.filter_topics(request.user, Topic.objects.all()), pk=topic_id)
    topic.subscribers.remove(request.user)
    msg = _('Subscription removed. You will not receive emails from this topic unless you subscribe or post again.')
    messages.success(request, msg, fail_silently=True)
    return HttpResponseRedirect(topic.get_absolute_url())


@login_required
def add_subscription(request, topic_id):
    topic = get_object_or_404(perms.filter_topics(request.user, Topic.objects.all()), pk=topic_id)
    if not perms.may_subscribe_topic(request.user, topic):
        raise PermissionDenied
    topic.subscribers.add(request.user)
    msg = _('Subscription added. You will receive email notifications for replies to this topic.')
    messages.success(request, msg, fail_silently=True)
    return HttpResponseRedirect(topic.get_absolute_url())


@login_required
def post_ajax_preview(request):
    content = request.POST.get('data')
    html = util._get_markup_formatter()(content)
    return render(request, 'pybb/_markitup_preview.html', {'html': html})


@login_required
def mark_all_as_read(request):
    for forum in perms.filter_forums(request.user, Forum.objects.all()):
        forum_mark, new = ForumReadTracker.objects.get_or_create_tracker(forum=forum, user=request.user)
        forum_mark.save()
    TopicReadTracker.objects.filter(user=request.user).delete()
    msg = _('All forums marked as read')
    messages.success(request, msg, fail_silently=True)
    return redirect(reverse('pybb:index'))


@login_required
@require_POST
def block_user(request, username):
    user = get_object_or_404(User, **{username_field: username})
    if not perms.may_block_user(request.user, user):
        raise PermissionDenied
    user.is_active = False
    user.save()
    if 'block_and_delete_messages' in request.POST:
        # individually delete each post and empty topic to fire method
        # with forum/topic counters recalculation
        posts = Post.objects.filter(user=user)
        topics = posts.values('topic_id').distinct()
        forums = posts.values('topic__forum_id').distinct()
        posts.delete()
        Topic.objects.filter(user=user).delete()
        for t in topics:
            try:
                Topic.objects.get(id=t['topic_id']).update_counters()
            except Topic.DoesNotExist:
                pass
        for f in forums:
            try:
                Forum.objects.get(id=f['topic__forum_id']).update_counters()
            except Forum.DoesNotExist:
                pass


    msg = _('User successfuly blocked')
    messages.success(request, msg, fail_silently=True)
    return redirect('pybb:index')


@login_required
@require_POST
def unblock_user(request, username):
    user = get_object_or_404(User, **{username_field: username})
    if not perms.may_block_user(request.user, user):
        raise PermissionDenied
    user.is_active = True
    user.save()
    msg = _('User successfuly unblocked')
    messages.success(request, msg, fail_silently=True)
    return redirect('pybb:index')


class UserEditPrivilegesView(generic.edit.FormMixin, generic.edit.ProcessFormView, generic.DetailView):

    template_name = 'pybb/edit_privileges.html'
    form_class = ModeratorForm
    model = User
    slug_field = 'username'
    slug_url_kwarg = 'username'

    def get_success_url(self):
        return reverse('pybb:edit_privileges', kwargs={'username': self.object.username})

    def get_initial(self):
        initial = super(UserEditPrivilegesView, self).get_initial()
        categories = Category.objects.all()
        for category in categories:
            initial['cat_%d' % category.pk] = category.forums.filter(moderators=self.object.pk)
        return initial

    def get_form_kwargs(self):
        form_kwargs = super(UserEditPrivilegesView, self).get_form_kwargs()
        form_kwargs['user'] = self.request.user
        return form_kwargs

    def get(self, request, *args, **kwargs):
        self.object = self.get_object()
        return super(UserEditPrivilegesView, self).get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        return super(UserEditPrivilegesView, self).post(request, *args, **kwargs)

    def form_valid(self, form):
        form.process(self.object)
        messages.success(self.request, _("Privileges updated"))
        return super(UserEditPrivilegesView, self).form_valid(form)
