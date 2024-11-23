import React from "react";
import MetaData from "./layout/MetaData.jsx";

const Home = () => {
  return (
    <>
    <MetaData title={'Os melhores produtos'}/>
      <div className="container">
        <div className="row">
          <div className="col-12 col-sm-6 col-md-12">
            <h1 id="products_heading" className="text-secondary">
              Últimos Produtos
            </h1>
            <section id="products" className="mt-5">
              <div className="row">
                <div className="col-sm-12 col-md-6 col-lg-3 my-3">
                  <div className="card p-3 rounded">
                    <img
                      className="card-img-top mx-auto"
                      src="./images/default_product.png"
                      alt=""
                    />
                    <div className="card-body ps-3 d-flex justify-content-center flex-column">
                      <h5 className="card-title">
                        <a href="">Nome do Produto</a>
                      </h5>
                      <div className="ratings mt-auto d-flex">
                        <div className="star-ratings">
                          <i className="fa fa-star star-active"></i>
                          <i className="fa fa-star star-active"></i>
                          <i className="fa fa-star star-active"></i>
                          <i className="fa fa-star star-active"></i>
                          <i className="fa fa-star star-active"></i>
                        </div>
                        <span id="no_of_reviews" className="pt-2 ps-2">
                          {" "}
                          (0){" "}
                        </span>
                      </div>
                      <p className="card-text mt-2">$100</p>
                      <a href="" id="view_btn" className="btn btn-block">
                        Veja Detalhes
                      </a>
                    </div>
                  </div>
                </div>
              </div>
            </section>
          </div>
        </div>
      </div>
    </>
  );
};

export default Home;
