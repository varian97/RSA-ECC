import math


class Point(object):

    def __init__(self, x, y):
        self.X = x
        self.Y = y

    def __str__(self):
        return "Point(%s,%s)"%(self.X, self.Y)

    def distance(self, p):
        dx = self.X - p.X
        dy = self.Y - p.Y
        return math.hypot(dx, dy)

