import { Injectable } from "@angular/core";
// import { products } from '../products';
import { HttpClient } from '@angular/common/http';
import { RouteReuseStrategy } from '@angular/router';
import { Location } from '@angular/common';
import { Observable, of, BehaviorSubject, Subject } from 'rxjs';

@Injectable({
    providedIn:'root'
})

export class CartService{
    baseUrl:string = "http://localhost:3001";
   // Product = products;
    items : any = [];
    cartitems : any = [];

    myMethod$: Observable<any>;
    private myMethodSubject = new Subject<any>();
    
   // private messageSource = new BehaviorSubject('abc');
   // currentMessage = this.messageSource.asObservable();
  
    constructor(private http: HttpClient, private _location: Location){
        this.myMethod$ = this.myMethodSubject.asObservable();
    }

    myMethod(data) {
        console.log(data); // I have data! Let's return it so subscribers can use it!
        // we can do stuff with data if we want
        this.myMethodSubject.next(data);
        console.log(data); 
    }

    changeMessage(message: any) {
    //    this.messageSource.next(message)
      }

    addToCart(Product){
        this.items.push(Product);
        localStorage.setItem('productItem',Product.length);
    }

    getItems(){
        console.log('items',this.items);
        localStorage.getItem('productItem');
        return this.items;
    }

    clearCart(){
        this.items = [];
        localStorage.removeItem('productItem');
        return this.items;
    }

    backButton(){
        this._location.back();
    }

    // getItemLength(): Observable<any[]>{
    //     //console.log(this.items.length);
    //     return of(this.cartitems);
        
    // }

    // get_products(){
    //     return this.http.get(this.baseUrl + '/products');
    // }
}