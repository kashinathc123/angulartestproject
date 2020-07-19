// import { async, ComponentFixture, TestBed } from "@angular/core/testing";
// import { RouterTestingModule } from "@angular/router/testing";

// import { ProductListComponent } from "./product-list.component";
// import { ProductService } from "../productService";
// import { FormsModule } from "@angular/forms";
// import { SharedModule } from "src/app/shared/shared.module";
// import { CommonModule } from "@angular/common";
// import { By } from "@angular/platform-browser";

// let sampleProducts = [
//   {
//     id: 3,
//     product: "Scooty"
//   },
//   {
//     id: 1,
//     product: "Bottle"
//   },
//   {
//     id: 2,
//     product: "Bag"
//   }
// ];

// let sortedProducts = [
//   {
//     id: 1,
//     product: "Bottle"
//   },
//   {
//     id: 2,
//     product: "Bag"
//   },
//   {
//     id: 3,
//     product: "Scooty"
//   }
// ];

// xdescribe("ProductListComponent", () => {
//   let component: ProductListComponent;
//   let fixture: ComponentFixture<ProductListComponent>;

//   let fakeDisplayname = "Product List";
//   const ProductServiceMock = {
//     get_products() {
//       return [
//         {
//           id: 1,
//           product: "Bottle"
//         },
//         {
//           id: 2,
//           product: "Bag"
//         },
//         {
//           id: 3,
//           product: "Scooty"
//         }
//       ];
//     }
//   };
//   beforeEach(async(() => {
//     TestBed.configureTestingModule({
//       imports: [CommonModule, RouterTestingModule, FormsModule, SharedModule],
//       declarations: [ProductListComponent],
//       providers: [{ provide: ProductService, useValue: ProductServiceMock }]
//     }).compileComponents();
//     fixture = TestBed.createComponent(ProductListComponent);
//     component = fixture.componentInstance;
//   }));

//   it("should create the productList", () => {
//     const fixture = TestBed.createComponent(ProductListComponent);
//     const comp = fixture.componentInstance;
//     expect(comp).toBeTruthy();
//     fixture.detectChanges();
//   });

//   it("should be String value for Page Title as displayName", () => {
//     const compiled = fixture.debugElement.nativeElement;
//     fixture.detectChanges();
//     component.displayName = fakeDisplayname;
//     fixture.detectChanges();
//     expect(compiled.querySelector("h3").textContent).toContain(
//       component.displayName
//     );
//   });

//   it("verify the productlist is null or undefined in productList component", function() {
//     component.orderedList = sortedProducts;
//     expect(component.orderedList.length).toBeGreaterThan(1);
//     expect(ProductServiceMock.get_products().length).toBeGreaterThan(1);
//   });

//   it("Verify the list should be displayed for atleast one item", function() {
//     expect(ProductServiceMock.get_products().length).toBeGreaterThan(1);
//   });

//   it("should be match search Term", () => {
//     const inEl = fixture.debugElement.query(By.css("#searchText"));
//     let inElval = inEl.nativeElement.value;
//     inElval = sortedProducts[0].product;
//     fixture.detectChanges();
//     expect(inElval).toEqual(sortedProducts[0].product);
//   });
// });
