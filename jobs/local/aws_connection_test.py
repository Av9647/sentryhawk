
# Examples of Spark with AWS Glue

# Imports
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import DateType

S3_INPUT_DATA = 's3://cyber-threat-intelligence/raw_data/'
S3_OUTPUT_DATA = 's3://cyber-threat-intelligence/staging_data/'

def main():

    # Creating the SparkSession
    spark = SparkSession.builder.appName("My Demo ETL App").getOrCreate()
    spark.sparkContext.setLogLevel('ERROR')

    # Spark DataFrame (Raw) - Transformation
    df = spark.read.option("Header", True).option("InferSchema", True).csv(S3_INPUT_DATA)

    # Define a dictionary of replacements to replace spaces in column names with underscores
    replacements = {c:c.replace(' ','_') for c in df.columns if ' ' in c}

    # Select columns from the dataframe using the replacements dictionary to rename columns with spaces
    df = df.select([F.col(c).alias(replacements.get(c, c)) for c in df.columns])

    # Convert the "Date" column from string type to date type
    df = df.withColumn("Date", F.to_date(F.col("Date"), "M/d/yyyy"))

    # Calculate the total sales by salesperson
    sales_by_salesperson = df.groupBy("Salesperson").agg(F.sum("Forecasted_Monthly_Revenue").alias("Total_Sales"))

    # Calculate the average revenue per opportunity stage
    avg_revenue_by_stage = df.groupBy("Opportunity_Stage").agg(F.avg("Weighted_Revenue").alias("Avg_Revenue"))

    # Filter the dataset to include only closed opportunities
    closed_opportunities = df.filter(F.col("Closed_Opportunity") == True)

    # Select specific columns for the cleaned dataset
    cleaned_df = df.select("Date", "Salesperson", "Segment", "Region", "Opportunity_Stage", "Weighted_Revenue")

    # Print the total number of records in the cleaned dataset
    print(f"Total no. of records in the cleaned dataset is: {cleaned_df.count()}")

    try:
        # Save the DataFrames under different folders within the S3_OUTPUT_DATA bucket
        sales_by_salesperson.write.mode('overwrite').parquet(S3_OUTPUT_DATA + "/sales_by_salesperson")
        avg_revenue_by_stage.write.mode('overwrite').parquet(S3_OUTPUT_DATA + "/avg_revenue_by_stage")
        closed_opportunities.write.mode('overwrite').parquet(S3_OUTPUT_DATA + "/closed_opportunities")
        cleaned_df.write.mode('overwrite').parquet(S3_OUTPUT_DATA + "/cleaned_df")
        print('The cleaned data is uploaded')
    except:
        print('Something went wrong, please check the logs :P')

if __name__ == '__main__':
    main()
