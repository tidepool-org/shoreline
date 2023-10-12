db = db.getSiblingDB('user');

db.tokens.deleteMany({
    expiresAt: { $lt: new Date().getTime() / 1000 }
});

db.tokens.find().forEach(token => {
    const expireDate = new Date(token.expiresAt * 1000)
    db.tokens.updateOne(
        { _id: token._id },
        { $set: {
            expiresTime: expireDate
          }
        }
      )
});
