from django import template
register = template.Library()




# to filter a queryset and return it back to template tags
@register.filter(name='filterInQuerySet')
def filterInQuerySet(QueryData, elem):
    newData = QueryData.filter(category=elem)
    return newData