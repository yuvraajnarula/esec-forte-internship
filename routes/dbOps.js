const express = require('express');
const router = express.Router();

router.post('/create', async (req,res)=>{
    try{
        
    }
    catch(err){
        res.status(500).json({error: `${err.message}`});
    }
})
module.exports = router;