import { Component, OnInit } from "@angular/core";
import { CartService } from "./cartComponent.service";

@Component({
  selector: "cart-component",
  templateUrl: "./CartComponent.html",
  styleUrls: ["./CartComponent.scss"]
})
export class CartComponent implements OnInit {
  displayName = "Cart Component";
  private products = <any>[];
  items = <any>[];
  itemLength;
  public data: Array<any> = this.itemLength;
  itemFlag: boolean;
  itemFlagClearCart: boolean;

  constructor(private cartservice: CartService) {}

  ngOnInit() {
    this.items = this.cartservice.getItems();
    this.itemLength = this.items.length;
    this.cartservice.myMethod(this.items);
    this.itemFlag = this.items.length >= 1 ? true : false;
  }

  clearCart() {
    alert("Clear cart");
    this.items = [];
    this.itemFlag = false;
    this.cartservice.myMethod(this.items);
    return this.cartservice.clearCart();
  }
}
