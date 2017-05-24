import time

from django import template
register = template.Library()


def epoch_datetime(epoch):
    try:
        return time.strftime('%d-%m-%Y %H:%M:%S', time.localtime(epoch))
    except TypeError:
        return None

register.filter(epoch_datetime)
