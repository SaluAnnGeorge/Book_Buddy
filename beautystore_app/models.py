from decimal import Decimal
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.validators import MinLengthValidator


class Seller(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True)
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    phone_no = models.CharField(max_length=12, unique=True, validators=[MinLengthValidator(10)])
    address = models.CharField(max_length=255)
    
    def __str__(self):
        return self.name
    
class Category(models.Model):
    category_name = models.CharField(max_length=100, unique=True)
    
    def __str__(self):
        return self.category_name

class Subcategory(models.Model):
    subcategory_name = models.CharField(max_length=100)
    parent_category = models.ForeignKey(Category, on_delete=models.CASCADE)
    
    def __str__(self):
        return self.subcategory_name


# Create your models here.
class Product(models.Model):
    name = models.CharField(max_length=255)
    author = models.CharField(max_length=255)
    price = models.FloatField()
    stock = models.IntegerField()
    image = models.ImageField(upload_to='product_images/')
    description = models.TextField()
    quantity_available = models.PositiveIntegerField(default=0)
    published_date = models.DateField(null=True, blank=True)
    genre = models.CharField(max_length=255, null=True, blank=True)  # Genre of the book
    isbn = models.CharField(max_length=13, unique=True)
    publisher = models.CharField(max_length=255, null=True, blank=True)
    page_count = models.PositiveIntegerField(null=True, blank=True)
    country_of_origin = models.CharField(max_length=255, null=True, blank=True)
    seller = models.ForeignKey(Seller, on_delete=models.CASCADE)
    subcategory = models.ForeignKey(Subcategory, on_delete=models.CASCADE)
    quantity_in_stock = models.PositiveIntegerField(default=0)
    reorder_level = models.PositiveIntegerField(default=0)
    cost = models.DecimalField(max_digits=10, decimal_places=2,default=100)

    def __str__(self):
        return self.name
    
    def stock_status(self):
        if self.quantity_in_stock == 0:
            return "Out of Stock"
        elif self.quantity_in_stock <= self.reorder_level:
            return "Low Stock"
        else:
            return "In Stock"

    

    
    

    
class Offer(models.Model):
    code = models.CharField(max_length=16)
    description = models.CharField(max_length=255)
    discount = models.FloatField()


class Wishlist(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)

    def __str__(self):
        return f'{self.user.username} Wishlist'
    
    
class Address(models.Model):
    recepient_name = models.CharField(max_length=100, null=True)
    recepient_contact = models.CharField(max_length=20, null=True)
    address_line1 = models.CharField(max_length=255)
    address_line2 = models.CharField(max_length=255, blank=True, null=True)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=20)
    customer = models.ForeignKey('Customer', on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return f"{self.address_line1}, {self.address_line2}, {self.city}, {self.state} - {self.postal_code}"    

class Customer(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True)
    customer_name = models.CharField(max_length=100)
    contact_number = models.CharField(max_length=20, blank=True, null=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    role = models.CharField(max_length=50, default='customer')

    def __str__(self):
        return self.customer_name
    
class Cart(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.IntegerField(default=0)

    def sub_total(self):
        return int(self.product.price) * int(self.quantity)

    def __str__(self):
        return f"Cart - Customer: {self.customer.customer_name} - Product: {self.product.product_name} - Qty: {self.quantity}"


class Order(models.Model):
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Placed', 'placed'),
        ('Shipped', 'Shipped'),
        ('Delivered', 'Delivered'),
    ]
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    address = models.ForeignKey(Address, on_delete=models.CASCADE)
    order_date = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')

    def total_price(self):
        return sum(item.total_price() for item in self.orderitem_set.all())

    def __str__(self):
        return f"Order - Customer: {self.customer.customer_name} - Status: {self.status}"

class OrderItem(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()

    def total_price(self):
        return self.product.price * self.quantity

    def __str__(self):
        return f"Order Item - Order: {self.order.id} - Product: {self.product.name} - Qty: {self.quantity}"



# Define the PurchaseOrder model
class PurchaseOrder(models.Model):
    TotalAmount = models.DecimalField(max_digits=20, decimal_places=2)
    PurchaseOrderDate = models.DateField()
    Status = models.CharField(max_length=250, blank=True)
    ExpectedDeliveryDate = models.DateField(blank=True, null=True)
    Seller = models.ForeignKey(Seller, on_delete=models.CASCADE)
    seller_message = models.TextField(blank=True)
    
    def __str__(self):
        return f"Purchase Order {self.id}"

class PurchaseOrderItem(models.Model):
    Quantity = models.IntegerField()
    Product = models.ForeignKey(Product, on_delete=models.CASCADE)
    PurchaseOrder = models.ForeignKey(PurchaseOrder, on_delete=models.CASCADE)
    PurchaseUnitPrice = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    TotalAmount = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)

    def save(self, *args, **kwargs):
        # Calculate total amount before saving
        if self.Quantity is not None and self.PurchaseUnitPrice is not None:
            self.TotalAmount = Decimal(self.Quantity) * Decimal(self.PurchaseUnitPrice)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Purchase Order Item {self.id}"