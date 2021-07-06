 const express = require('express')
 const app = express()
 const port = 5000


 const mongoose = require('mongoose')
 mongoose.connect(' mongodb+srv://hee:cjt shem js@boilerplate.obwby.mongodb.net/myFirstDatabase?retryWrites=true&w=majority', {
     useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true, useFindAndModify: false
 }).then(() => console.log('MongoDB connected...'))
   .catch(err => console.log(err))


 app.get('/', (req, res) => res.send('Hello Word!~~안녕하세요~~'))

 app.listen(port, () => console.log(`Example app listening on port ${port}!`))