const jwt = require('jsonwebtoken');

//VERIFY TOKEN ALL
function all(req,res,next){
    const token = req.header('authorization');
    if(!token){
        res.status(401).json( {state: 'error', message: 'token not found' })
    }
    else{
        jwt.verify(token, 'secretkey',(err,auth)=>{
            if(err){res.status(400).json( {state: 'error', message: 'invalid token' })}
            else{
                console.log(auth);
                req.auth = auth;
                next()
            }
        });
    }
}

//VERIFY TOKEN USER
function user(req,res,next){
    const token = req.header('authorization');
    if(!token){
        res.status(401).json( {state: 'error', message: 'token not found' })
    }
    else{
        jwt.verify(token, 'secretkey',(err,auth)=>{
            if(err){res.status(400).json( {state: 'error', message: 'invalid token' })}
            else{
                if(auth.admin){
                    res.status(400).json( {state: 'error', message: 'admin not authorized' })
                }
                else{
                    console.log(auth);
                    req.auth = auth;
                    next()
                }
            }
        });
    }
}

//VERIFY TOKEN ADMIN
function admin(req,res,next){
    const token = req.header('authorization');
    if(!token){
        res.status(401).json( {state: 'error', message: 'token not found' })
    }
    else{
        jwt.verify(token, 'secretkey',(err,auth)=>{
            if(err){res.status(400).json( {state: 'error', message: 'invalid token' })}
            else{
                if(!auth.admin){
                    res.status(400).json( {state: 'error', message: 'user not authorized' })
                }
                else{
                    console.log(auth);
                    req.auth = auth;
                    next()
                }
            }
        });
    }
}

module.exports = {all , user , admin};