import joi from "joi";

// validate from entering wrong data into the database
const Signupvalidation = (req, res, next) => {
  const Schema = joi.object({
    username: joi.string().min(3).max(100).required(),
    email: joi.string().email().required(),
    password: joi.string().min(2).max(30).required()
  });

  const { error } = Schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }
  next();
};

const loginValidation = (req, res, next) => {
  const Schema = joi.object({
    email: joi.string().email(),
   
    password: joi.string().min(3).max(30).required()
  })

  const { error } = Schema.validate(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }
  next();
};

export { Signupvalidation, loginValidation };