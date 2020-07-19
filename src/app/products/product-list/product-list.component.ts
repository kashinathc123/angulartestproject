import { Component, OnInit, OnDestroy, ViewChild, ChangeDetectorRef } from "@angular/core";
import { takeUntil, startWith } from "rxjs/operators";
import { Subject } from "rxjs";

import { ProductService } from "../productService";
//import { MatTableDataSource } from '@angular/material/table';
import { Product } from '../model/products';
//import { MatPaginator } from '@angular/material/paginator';
import { MatSort } from '@angular/material/sort';
import {MatPaginator, MatTableDataSource} from '@angular/material';

// export interface Element {
//   name: string;
//   position: number;
//   weight: number;
//   symbol: string;
// }

@Component({
  selector: "app-product-list",
  templateUrl: "./product-list.component.html",
  styleUrls: ["./product-list.component.css"]
})
export class ProductListComponent implements OnInit {
  //ELEMENT_DATA;
  displayedColumns = ['id', 'productName', 'size', 'category', 'quantity','color','price'];
  dataSource: MatTableDataSource<Product> | null;
  index: number;
  id: number;
  dataLength: number;
  // dataSource: MatTableDataSource<Product>;
 
  loading: boolean;
  displayName = "Product List";
  productList;
  orderedList = [];
  query: string = "";
  private ngUnsubscribe = new Subject();

 // displayedColumns = ['position', 'name', 'weight', 'symbol'];
 // dataSource;

  // @ViewChild(MatSort, {static: true}) sort: MatSort;

 //@ViewChild(MatPaginator,{static:true}) paginator: MatPaginator;

  constructor(private productService: ProductService) {
    //this.dataSource = new MatTableDataSource(this.productList);
  }

  @ViewChild(MatPaginator, {static: true}) paginator: MatPaginator;
  @ViewChild(MatSort, {static: true}) sort: MatSort;

  ngAfterViewInit() {
    //this.dataSource = new MatTableDataSource<Product>(this.productList);
   // this.dataSource.paginator = this.paginator;
  }

  ngOnInit() {
   this.getProducts_onLoad();   
  // console.log(this.dataSource);
  // this.dataSource = new MatTableDataSource<Product>(this.productList);
  }

  /**
   * Get ProductList from API on Page loading event
   */
  public getProducts_onLoad() {
    this.loading = true;   
      this.productService
        .get_products()
        .pipe(takeUntil(this.ngUnsubscribe))
        .subscribe((res:any) => {
          this.loading = false;
          if (!res) return;
          this.productList = res;
          this.dataSource = new MatTableDataSource(this.productList);
          this.dataLength = this.productList.length;
          console.log(this.dataLength);
         // this.dataSource.paginator = this.paginator;
          console.log("Fetched ProductList: ", this.productList);

          this.dataSource.paginator = this.paginator;
          this.dataSource.sort = this.sort;
         // this.sortBy("id");
        });   
  }

  /**
   * Sorting the product list
   */
  // sortBy(field: string) {
  //   this.productList.sort((a: any, b: any) => {
  //     if (a[field] < b[field]) {
  //       return -1;
  //     } else if (a[field] > b[field]) {
  //       return 1;
  //     } else {
  //       return 0;
  //     }
  //   });
  //   this.orderedList = this.productList;
  // }

  // material sort
  applyFilter(event: Event) {
    const filterValue = (event.target as HTMLInputElement).value;
    this.dataSource.filter = filterValue.trim().toLowerCase();

    if (this.dataSource.paginator) {
      this.dataSource.paginator.firstPage();
    }
  }

  // ngAfterViewInit() {
  //   setTimeout(() => this.dataSource.paginator = this.paginator);
  // }

  

  /**
   * Unsubscribe the Subscribed data on ngOnDestroy method
   */
  // ngOnDestroy() {
  //   this.ngUnsubscribe.next();
  //   this.ngUnsubscribe.complete();
  // }

}