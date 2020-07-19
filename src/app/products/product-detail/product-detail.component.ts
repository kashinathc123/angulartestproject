import { Component, OnInit } from "@angular/core";
import { ActivatedRoute, Router } from "@angular/router";
import { ProductService } from "../productService";
import { takeUntil, startWith, take, map, count } from "rxjs/operators";
import { Subject } from "rxjs";
import { CartService } from '../cartComponent/cartComponent.service';

@Component({
  selector: "app-product-detail",
  templateUrl: "./product-detail.component.html",
  styleUrls: ['./product-detail.component.css']
})
export class ProductDetailComponent implements OnInit {
  displayName = "Product Detail";
  product;
  productList;
  private ngUnsubscribe = new Subject();

  constructor(
    private route: ActivatedRoute,
    private productService: ProductService,
    private router: Router,
    private cartService: CartService
  ) {}

/**
   * get fetch the product list from API and pass the route param to id
   */
  ngOnInit() {
    this.route.params.subscribe(params => {
      let id = params["id"];
      this.productService
        .get_products()
        .pipe(startWith([]), takeUntil(this.ngUnsubscribe))
        .subscribe(res => {
          this.productList = res;
          this.getProduct(id);
        });
    });
  }

  /**
   * get Id, filter with the productList and match with correct product id/index
   */
  getProduct(id) {
    this.product = this.productList.filter(x => x.id == id)[0];
  }

  goEdit(){
    this.router.navigate(['/edit']);
  }

  addToCart(product){
    window.alert('Product has been added to cart !!!');
    console.log('product', this.product);
    this.cartService.addToCart(product);
}

  deleteProduct(product){
    console.log('deleteproduct',product);
    this.productService.deleteProductData(product).subscribe(
      (res) => console.log("user deleted", res)
    )
  }

  /**
   * Unsubscribe the Subscribed data on ngOnDestroy method
   */
  ngOnDestroy() {
    this.ngUnsubscribe.next();
    this.ngUnsubscribe.complete();
  }

}
