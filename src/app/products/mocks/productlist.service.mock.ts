import { Injectable } from '@angular/core';

@Injectable()
export class ProductServiceMock {
  constructor() { }

  get_products(): Array<{}> {
      return [
        {
          id: 2,
          imgUrl: "../../../assets/images/product.jpg",
          product: "Bottle",
          supplierId: 1,
          categoryId: 551,
          unit: "24 - 12 oz bottles",
          price: 19
        }
      ];
  }
}