import { async, ComponentFixture, TestBed, inject } from '@angular/core/testing';

import { ProductDetailComponent } from './product-detail.component';
import { MaterialModule } from 'src/app/shared/core/material/material.module';
import { RouterTestingModule } from '@angular/router/testing';
import { ProductService } from '../productService';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { Router, ActivatedRoute } from '@angular/router';
import { By } from '@angular/platform-browser';
import { DebugElement } from '@angular/core';
import { Product } from '../model/products';
import { createComponent } from '@angular/compiler/src/core';

describe('ProductDetailComponent', () => {
  let component: ProductDetailComponent;
  let fixture: ComponentFixture<ProductDetailComponent>;
  let de: DebugElement;
  let service: ProductService;

  let httpMock: HttpTestingController;
  let baseUrl = 'http://localhost:3000/products';
  let dummyProduct: Product[] = [{
    "productId": 1,
    "productName": "Test Product",
    "price": "22",
    "color": "Green",
    "quantity": "33",
    "size": "Medium",
    "category": "Gifts",
    "id": 1
  }];

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports:[MaterialModule, RouterTestingModule, HttpClientTestingModule,
          RouterTestingModule.withRoutes([
              { path: 'products', component: ProductDetailComponent }
             ]) ],
    declarations: [ ProductDetailComponent ],
    providers: [ProductService]
  }).compileComponents();
    fixture = TestBed.createComponent(ProductDetailComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it(`should have as title 'product-detail'`, () => {
    expect(component.displayName).toEqual('Product Detail');
  });

  it('should not have product data', () => {
    const fixture = TestBed.createComponent(ProductDetailComponent);
    fixture.detectChanges();
    const compiled = fixture.nativeElement;
    fixture.detectChanges();
    expect(compiled.querySelector('.no-product').textContent).toContain('No such product available!!');
  });

  it('expects service to fetch/get product data', inject([HttpTestingController, ProductService],
    (httpMock, service) => {
      // We call the service
      service.get_products().subscribe((data: Product[]) => {
        expect(data.length).toBeGreaterThanOrEqual(1);
      });
      // We set the expectations for the HttpClient mock
      //const req = httpMock.expectOne('http://localhost:3000/products');
     // expect(req.request.method).toEqual('GET');
      // Then we set the fake data to be returned by the mock
     // httpMock.flush(dummyProduct);
     // httpMock.verify();     
    })
  );

});
