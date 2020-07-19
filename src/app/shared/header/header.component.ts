import { Component, OnInit } from '@angular/core';
import { CartService } from 'src/app/products/cartComponent/cartComponent.service';

@Component({
  selector: 'app-header',
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.scss']
})
export class HeaderComponent implements OnInit {
    itemLength;
    items = [];
    cartvalueLength = 0;
    public data : Array<any> = this.itemLength;

  constructor(private cartservice: CartService) {
      this.cartservice.myMethod$.subscribe((data) => {
        this.items = data;
        this.cartvalueLength = data.length; // And he have data here too!
         console.log('this.itemLength',data);
     });
   
   }

  ngOnInit() {
    //this.itemLength = localStorage.getItem('productItem');
   //console.log('itemLength;', this.itemLength);
   
  }

}
