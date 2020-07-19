import { TestBed, inject } from '@angular/core/testing';
import { HttpTestingController, HttpClientTestingModule } from '@angular/common/http/testing';
import { ProductService } from './productService';
import { HttpClientModule } from '@angular/common/http';
import { Product } from './model/products';

describe('ProductService', () => {
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
    let dummypostProduct = {
      "productId": 1,
      "productName": "Test Product",
      "price": "22",
      "color": "Green",
      "quantity": "33",
      "size": "Medium",
      "category": "Gifts",
      "id": 1
    };
    let dummydeletetProduct = {
      "productId": 1,
      "productName": "Pen",
      "price": "22",
      "color": "Green",
      "quantity": "33",
      "size": "Medium",
      "category": "Gifts",
      "id": 1
    };
   // const service: ProductService = TestBed.get(ProductService);
   beforeEach(() => {
    TestBed.configureTestingModule({
        imports: [HttpClientTestingModule],
        providers: [ProductService]
    });
    service = TestBed.get(ProductService);
    httpMock = TestBed.get(HttpTestingController);
  });

  it('should be created', () => {
    const service: ProductService = TestBed.get(ProductService);
    expect(service).toBeTruthy();
  });

  // xit("should get product list", () => {    
  //   service.get_products().subscribe((res: Product[]) => {
  //     console.log(res.length);
  //       expect(res.length).toBeGreaterThanOrEqual(1);
  //       expect(res[0].productName).toEqual(dummyProduct[0].productName);   
  //    });
  // });

  // xit('be able to retrieve posts', () => {   
  //   service.createProduct(dummyProduct).subscribe((res: Product[]) => {
  //       expect(res.length).toBe(2);
  //       expect(res).toEqual(dummyProduct);
  //   });
  //   const request = httpMock.expectOne( `${service.baseUrl}/products`);
  //   expect(request.request.method).toBe('GET');
  //   request.flush(dummyProduct);
  //   });

  //   afterEach(() => {
  //     httpMock.verify();
  // });


  it('expects service to fetch/get product data', inject([HttpTestingController, ProductService],
    (httpMock, service) => {
      // We call the service
      service.get_products().subscribe((data: Product[]) => {
        expect(data.length).toBeGreaterThanOrEqual(1);
      });
      // We set the expectations for the HttpClient mock
      const req = httpMock.expectOne(`${service.baseUrl}/products`);
      expect(req.request.method).toEqual('GET');
      // Then we set the fake data to be returned by the mock
      req.flush(dummyProduct);
     
    })
  );

  it('expects service to create product', inject([HttpTestingController, ProductService],
    (httpMock, service) => {
      // We call the service
      service.createProduct().subscribe((data: Product[]) => {
        console.log('created product', data);
       expect(data[0].id).toBe(dummypostProduct.id);
       expect(data[0].productId).toBe(dummypostProduct.productId);
       expect(data[0].color).toBe(dummypostProduct.color);
       expect(data[0].quantity).toBe(dummypostProduct.quantity);
       expect(data[0].size).toBe(dummypostProduct.size);
       expect(data[0].category).toBe(dummypostProduct.category);
       expect(data[0].price).toBe(dummypostProduct.price);
       expect(data.length).toBe(7);
      });
      // We set the expectations for the HttpClient mock
      const req = httpMock.expectOne(baseUrl, dummypostProduct);
      expect(req.request.method).toEqual('POST');
      // Then we set the fake data to be returned by the mock
      req.flush(dummypostProduct);
     
    })
  );

  it('expects service to update product data', inject([HttpTestingController, ProductService],
    (httpMock, service) => {
      // We call the service
      service.UpdateProductData(dummypostProduct).subscribe((data: Product[]) => {
      console.log('updated product', data);
      expect(data[0].id).toBe(dummypostProduct.id);
      expect(data[0].productId).toBe(dummypostProduct.productId);
      expect(data[0].color).toBe(dummypostProduct.color);
      expect(data[0].quantity).toBe(dummypostProduct.quantity);
      expect(data[0].size).toBe(dummypostProduct.size);
      expect(data[0].category).toBe(dummypostProduct.category);
      expect(data[0].price).toBe(dummypostProduct.price);
      expect(data.length).toBe(7);
      });
      // We set the expectations for the HttpClient mock
      const req = httpMock.expectOne(`${service.baseUrl}/products/${dummypostProduct.productId}`, dummypostProduct);
      expect(req.request.method).toEqual('PUT');
      // Then we set the fake data to be returned by the mock
      req.flush(dummypostProduct);
     
    })
  );

  it('expects service to delete product data', inject([HttpTestingController, ProductService],
    (httpMock, service) => {
      // We call the service
      service.deleteProductData(dummydeletetProduct).subscribe(data => {
        console.log('deleted product', data);
       expect(data.id).toBe(dummydeletetProduct.id);     
      });
      // We set the expectations for the HttpClient mock
      const req = httpMock.expectOne(`${service.baseUrl}/products/${dummydeletetProduct.productId}`);
      expect(req.request.method).toEqual('DELETE');
      // Then we set the fake data to be returned by the mock
      req.flush(dummydeletetProduct);
     
    })
  );

  afterEach(inject([HttpTestingController], (httpMock: HttpTestingController) => {
    httpMock.verify();
  }));
  
});
