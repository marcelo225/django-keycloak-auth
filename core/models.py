from django.db import models


class Bank(models.Model):
    code = models.CharField(max_length=5, null=False)
    name = models.CharField(max_length=100, null=False)

    def __str__(self):
        return '%s %s' % (self.code, self.name)

    class Meta:
        db_table = 'tb_bank'
