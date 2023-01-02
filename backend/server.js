const express = require("express");
const app = express();
const mongoose = require("mongoose");
require("dotenv").config({});
const port = process.env.PORT || 8081;
const database = process.env.DBURL;
const bodyparser = require("body-parser");
app.use(bodyparser.json());
mongoose.set("strictQuery", false);
const productDatabase = require("./models/productModel");
const { json } = require("body-parser");
const userDataBase = require("./models/userModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookie = require("cookie-parser");
const { isAuthUser, isAdmin } = require("./middleWare/isAuth");
const nodeMailer = require("nodeMailer");
const OrderDateBase = require("./models/order");
const cors = require('cors');
app.use(cors());

app.use(cookie());

mongoose
  .connect(database, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("DataBase connection is successfully"))
  .catch((err) =>
    console.log("dataBase is not Connected due to ", err.message)
  );

// functions

function Generatetoken(id) {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE,
  });
}

async function updateStock(productId,quantity){
  const product = await productDatabase.findById(productId);
  product.stock = product.stock-quantity;
  await product.save({validateBeforeSave:false}); 
}

async function sendEmail(options) {
  const transporter = nodeMailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    service: process.env.MAIL_SERVICE,
    auth: {
      user: process.env.MAIL,
      pass: process.env.MAIL_PASSWORD,
    },
  });
  const mailOption = {
    from: process.env.MAIL,
    to: options.email,
    subject: options.subject,
    text: options.message,
  };

  await transporter.sendMail(mailOption);
}

// get all products
app.get("/products", async (req, res) => {
  try {
    let productCount = await productDatabase.countDocuments();
    if (req.query) {
      let { category, price, page } = req.query;
      let queryObject = {};
      if (price) {
        queryObject.price = { $gt: price.gt, $lt: price.lt };
      }

      if (category) {
        queryObject.category = { $regex: category, $options: "i" };
      }
      let skip = 0;
      if (page) {
        const currentPage = Number(page) || 1;
        skip = 5 * (currentPage - 1);
      }

      const product = await productDatabase
        .find(queryObject)
        .limit(5)
        .skip(skip);

      res.status(200).json({ success: true, product, productCount });
    } else {
      const product = await productDatabase.find({});
      res.status(200).json({ success: true, product, productCount });
    }
  } catch (error) {
    res.status(200).json({ success: false, msg: error.message });
  }
});

// GET PRODUCT BY ID

app.get("/product/:id", async (req, res, next) => {
  const product = await productDatabase.findById(req.params.id);
  if (!product) {
    return res.status(500).json({
      success: false,
      msg: "product not found or id must be invalid id",
    });
  } else {
    res.status(200).json({ success: true, product });
  }
});

// create a new products
app.post("/createProduct", isAuthUser, isAdmin, async (req, res) => {
  try {
    const product = await productDatabase.create(req.body);
    res.status(201).json({ success: true, product });
  } catch (error) {
    res.status(500).json({ success: false, msg: error.message });
  }
});

//update product by ID
app.put("/product/:id", isAuthUser, isAdmin, async (req, res) => {
  let product = await productDatabase.findById(req.params.id);

  if (!product) {
    res
      .status(500)
      .json({ success: false, msg: "product not found or id is invalid" });
  } else {
    product = await productDatabase.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
      useFindAndModify: false,
    });

    res.status(200).json({ success: true, product });
  }
});

// DELETE PRODUCT

app.delete("/product/:id", isAuthUser, isAdmin, async (req, res) => {
  const product = await productDatabase.findById(req.params.id);
  if (!product) {
    res
      .status(500)
      .json({ success: false, msg: "product not found or id invalid" });
  } else {
    await product.remove();
    res
      .status(200)
      .json({ success: true, msg: "product deleted successfully !" });
  }
});

//USER ROUTES STARTS

app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    hashPassword = await bcrypt.hash(password, 14);
    const user = await userDataBase.create({
      name,
      email,
      password: hashPassword,
      avatar: {
        public_id: "this is public id",
        url: "url of dp",
      },
    });

    const token = Generatetoken(user._id);
    res.status(201).cookie("token", token).json({ success: true, token });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

// LOGIN Routes

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(401).json({
        success: false,
        error: "please enter both email and password",
      });
    } else {
      const emailFound = await userDataBase
        .findOne({ email })
        .select("+password");
      if (emailFound) {
        const passwordMatch = await bcrypt.compare(
          password,
          emailFound.password
        );
        if (passwordMatch) {
          const token = Generatetoken(emailFound._id);
          return res
            .status(200)
            .cookie("token", token)
            .json({ success: true, token });
        } else {
          return res
            .status(401)
            .json({ success: false, error: "invalid user details" });
        }
      } else {
        return res
          .status(401)
          .json({ success: false, error: "invalid user details" });
      }
    }
  } catch (error) {
    return res.status(401).json({ success: false, error: error.message });
  }
});

//LOGOUT USER

app.get("/logout", (req, res) => {
  res.cookie("token", null, {
    expires: new Date(Date.now()),
    httpOnly: true,
  });
  res.status(200).json({ success: true, message: "logout successfully" });
});

app.post("/forgot", async (req, res) => {
  try {
    const user = await userDataBase.findOne({ email: req.body.email });
    if (!user) {
      return res.status().json({ success: false, message: "user not found" });
    } else {
      const resetToken = user.getResetToken();
      await user.save({ validateBeforeSave: false });
      const resetPasswordUrl = `${req.protocol}://${req.get(
        "host"
      )}/reset/${resetToken}`;
      const message = `Your password reset token is :-\n\n ${resetPasswordUrl} \n\n if you have not requested to this please ignore it`;
      try {
        await sendEmail({
          email: user.email,
          subject: "Ecom password recovery mail",
          message: message,
        });
        res.status(200).json({
          success: true,
          message: `email is send successfully to ${user.email}`,
        });
      } catch (error) {
        user.resetPasswordExpire = undefined;
        user.resetPasswordToken = undefined;
        await user.save({ validateBeforeSave: false });
        return res.status(401).json({ success: false, error: error.message });
      }
    }
  } catch (error) {
    return res.status().json({ success: false, error: error.message });
  }
});

// GET USER DETAIL

app.get("/me", isAuthUser, (req, res) => {
  const user = req.user;
  res.status(200).json({ success: true, user });
});

app.put("/updatepassword", isAuthUser, async (req, res) => {
  try {
    const { password, newpassword, confirmpassword } = req.body;
    const userPassword = await userDataBase
      .findById(req.user._id)
      .select("+password");
    const isPasswordMatch = await bcrypt.compare(
      password,
      userPassword.password
    );
    if (isPasswordMatch) {
      if (newpassword == confirmpassword) {
        const newHashPassword = await bcrypt.hash(newpassword, 14);
        userPassword.password = newHashPassword;
        await userPassword.save();
        res
          .status(200)
          .json({ success: true, msg: "password update successfully" });
      } else {
        res.status(400).json({
          success: false,
          msg: "new password and confirm password are not same",
        });
      }
    } else {
      res
        .status(401)
        .json({ success: false, msg: "old password does not match" });
    }
  } catch (error) {
    res.json({ error: error.message });
  }
});

//CREATE & UPDATE REVIEW

app.put("/review", isAuthUser, async (req, res) => {
  const { rating, comment, productId } = req.body;
  const review = {
    user: req.user._id,
    name: req.user.name,
    rating: Number(rating),
    comment,
  };

  const product = await productDatabase.findById(productId);

  const isReviewed = product.reviews.find(
    (rev) => rev.user.toString() == req.user._id.toString()
  );

  if (isReviewed) {
    console.log("if statment");
    product.reviews.map((item) => {
      if (item.user.toString() == req.user._id.toString()) {
        (item.rating = rating), (item.comment = comment);
      }
    });
  } else {
    product.reviews.push(review);
    product.numOfReviews = product.reviews.length;
  }

  let avg = 0;
  product.reviews.map((item) => {
    avg += item.rating;
  });
  product.ratings = avg / product.reviews.length;

  await product.save({ validateBeforeSave: false });

  res.status(200).json({ success: true, msg: "review updated" });
});

// GET ALL REVIEWS OF SINGLE PRODUCT

app.get("/productreview", async (req, res) => {
  try {
    const product = await productDatabase.findById(req.query.id);
    if (!product) {
      res.status(401).json({ success: false, msg: "product not found" });
    } else {
      res.status(200).json({ success: true, reviews: product.reviews });
    }
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

//DELETE REVIEW
app.delete("/deletereview", isAuthUser, async (req, res) => {
  try {
    const product = await productDatabase.findById(req.query.productId);
    if (!product) {
      res.status(401).json({ success: false, msg: "product not found" });
    } else {
      const reviews = product.reviews.filter(
        (item) => item._id.toString() != req.query.id.toString()
      );
      let avg = 0;
      reviews.map((item) => {
        avg += item.rating;
      });
      if (avg == 0) {
        ratings = 0;
      } else {
        const ratings = avg / reviews.length;
      }
      const numOfReviews = reviews.length;

      await productDatabase.findByIdAndUpdate(
        req.query.productId,
        { reviews, ratings, numOfReviews },
        {
          new: true,
          runValidators: true,
          useFindAndModify: true,
        }
      );
      res
        .status(200)
        .json({ success: true, msg: "review deleted successfully" });
    }
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

//ORDERS ROUTES

//CREATE NEW ORDER

app.post("/createorder", isAuthUser, async (req, res) => {
  try {
    const {
      shippingInfo,
      orderItems,
      paymentInfo,
      itemsPrice,
      taxPrice,
      shippingPrice,
      totalPrice,
    } = req.body;

    const order = await OrderDateBase.create({
      shippingInfo,
      orderItems,
      paymentInfo,
      itemsPrice,
      taxPrice,
      shippingPrice,
      totalPrice,
      paidAt: Date.now(),
      user: req.user._id,
    });

    res.status(201).json({ success: true, order });
  } catch (error) {
    res.status(400).json({ success: false, error: error.message });
  }
});

//GET SINGLE ORDER

app.get("/singleorder/:id", async (req, res) => {
  let order = await OrderDateBase.findById(req.params.id).populate("user");
  if (!order) {
    return res.status(400).json({
      success: false,
      msg: `order not found of this id ${req.params.id}`,
    });
  } else {
    return res.status(201).json({ success: true, order });
  }
});

//GET MY ORDERS (LOGIN USER)

app.get("/myorders", isAuthUser, async (req, res) => {
  try {
    const orders = await OrderDateBase.find({ user: req.user._id });
    if (orders.length>0) {
      return res.status(200).json({ success: true, orders });
    } else {
      return res.status(404).json({
        success: false,
        error: `orders not found for this user id ${req.user._id} `,
      });
    }
  } catch (error) {
    return res.status(400).json({ success: false, error: error.message });
  }
});


// GET ALL ORDERS -- ADMIN

app.get('/allorders',isAuthUser,isAdmin,async(req,res)=>{
 try {
  const orders = await OrderDateBase.find().populate('user');
  if(orders.length>0){
    let totalAmount = 0;
    orders.map(item=>totalAmount +=item.totalPrice);
    return res.status(200).json({success:true,orders,totalAmount});
  }else{
    return res.status(200).json({success:false,msg:'no orders found'})
  }
 } catch (error) {
  return res.status(200).json({success:false,error:error.message})
 }
});


// UPDATE ORDER AND STOCK

app.get('/updateorder/:id',isAuthUser,isAdmin,async(req,res)=>{
  const {status} = req.body;
  const id = req.params.id; 
  const order = await OrderDateBase.findById(id);
  if(!order){
    return res.status(401).send({success:false,msg:'order is not found'});
  }
  if(order.orderStatus=='Delivered'){
    return res.status(400).json({msg:'order is already delivered'})
  }
  
  order.orderItems.map (item=>{
    updateStock(item.product,item.quantity);
  })


 order.orderStatus = status;

 if(status=='Delivered'){
  order.deliveredAt = Date.now();
 }

 await order.save({validateBeforeSave:false});
 res.status(200).send({success:true,msg:'order is delivered successfully'});

});



// DELETE ORDER

app.delete('/deleteorder/:id',isAuthUser,isAdmin,async(req,res)=>{
 try {
  const order = await OrderDateBase.findById(req.params.id);
  if(order){
    await order.remove();
    return res.status(200).json({success:true,msg:"order deleted successfully"});
  }else{
    return res.status(400).json({success:false,error:`order not found of this id ${req.params.id}`})
  }
 } catch (error) {
  return res.status(401).json({success:false,error:error.message});
 }
})

// server listening
app.listen(port, () => {
  console.log("server is running at", port);
});
