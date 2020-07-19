import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Injectable({
  providedIn: 'root'
})
export class ProductService {

  baseUrl:string = "http://localhost:3000";

  constructor(private http : HttpClient) { 
    
  }
  
  get_products(){
    return this.http.get(this.baseUrl + '/products');
  }

  createProduct(product) {
    return  (this.http.post(this.baseUrl + '/products', product));
  }

  UpdateProductData(product){
    console.log(product);
    return  this.http.put(this.baseUrl + '/products/' + product.productId, product);
  }

  deleteProductData(product){
    console.log('finaldeleted',product);
    return this.http.delete(this.baseUrl + '/products/' + product.id);
  }

}
