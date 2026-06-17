# ---------------------------------------------------------------------------
# AWS Glue — Database and Table for CloudTrail Athena Queries
#
# Creates the Glue catalog database and table needed to query CloudTrail
# logs stored in S3 via Amazon Athena.
# ---------------------------------------------------------------------------

resource "aws_glue_catalog_database" "cloudtrail" {
  name        = "finops_cloudtrail"
  description = "Glue database for FinOps CloudTrail log queries via Athena"
}

resource "aws_glue_catalog_table" "cloudtrail_logs" {
  name          = "cloudtrail_logs"
  database_name = aws_glue_catalog_database.cloudtrail.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"             = "TRUE"
    "serialization.format" = "1"
    "classification"       = "cloudtrail"
  }

  storage_descriptor {
    location = "s3://${aws_s3_bucket.cloudtrail.id}/AWSLogs/${local.account_id}/CloudTrail/${local.region}/"
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "com.amazon.emr.hive.serde.CloudTrailSerde"
      parameters = {
        "serialization.format" = "1"
      }
    }

    columns {
      name = "eventversion"
      type = "string"
    }
    columns {
      name = "useridentity"
      type = "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>>>"
    }
    columns {
      name = "eventtime"
      type = "string"
    }
    columns {
      name = "eventsource"
      type = "string"
    }
    columns {
      name = "eventname"
      type = "string"
    }
    columns {
      name = "awsregion"
      type = "string"
    }
    columns {
      name = "sourceipaddress"
      type = "string"
    }
    columns {
      name = "useragent"
      type = "string"
    }
    columns {
      name = "errorcode"
      type = "string"
    }
    columns {
      name = "errormessage"
      type = "string"
    }
    columns {
      name = "requestparameters"
      type = "string"
    }
    columns {
      name = "responseelements"
      type = "string"
    }
    columns {
      name = "additionaleventdata"
      type = "string"
    }
    columns {
      name = "requestid"
      type = "string"
    }
    columns {
      name = "eventid"
      type = "string"
    }
    columns {
      name = "resources"
      type = "array<struct<arn:string,accountid:string,type:string>>"
    }
    columns {
      name = "eventtype"
      type = "string"
    }
    columns {
      name = "apiversion"
      type = "string"
    }
    columns {
      name = "readonly"
      type = "string"
    }
    columns {
      name = "recipientaccountid"
      type = "string"
    }
    columns {
      name = "serviceeventdetails"
      type = "string"
    }
    columns {
      name = "sharedeventid"
      type = "string"
    }
    columns {
      name = "vpcendpointid"
      type = "string"
    }
  }

  depends_on = [
    aws_s3_bucket.cloudtrail,
    aws_cloudtrail.finops,
  ]
}
