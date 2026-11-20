//! Tantivy full-text index over file name, hashes and detection names.
//! SQLite stays the source of truth; the index only maps a query to scan ids.

use std::path::Path;
use std::sync::Mutex;

use anyhow::Result;
use tantivy::collector::TopDocs;
use tantivy::query::{BooleanQuery, Occur, Query, QueryParser, RegexQuery};
use tantivy::schema::{Field, STORED, STRING, Schema, TEXT, Value};
use tantivy::{IndexReader, IndexWriter, ReloadPolicy, TantivyDocument, Term, doc};

use crate::model::ScanSummary;

pub struct Index {
    index: tantivy::Index,
    reader: IndexReader,
    writer: Mutex<IndexWriter>,
    id: Field,
    text: Field,
}

impl Index {
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let directory = tantivy::directory::MmapDirectory::open(dir)?;
        Self::from(tantivy::Index::open_or_create(directory, schema())?)
    }

    pub fn in_memory() -> Result<Self> {
        Self::from(tantivy::Index::create_in_ram(schema()))
    }

    fn from(index: tantivy::Index) -> Result<Self> {
        let s = index.schema();
        let reader = index.reader_builder().reload_policy(ReloadPolicy::Manual).try_into()?;
        let writer = index.writer(20_000_000)?;
        Ok(Self { id: s.get_field("id")?, text: s.get_field("text")?, index, reader, writer: Mutex::new(writer) })
    }

    /// Adds or replaces the scan's document.
    pub fn put(&self, scan: &ScanSummary) -> Result<()> {
        let f = &scan.file;
        let mut text = vec![f.name.as_str(), &f.mime, &f.md5, &f.sha1, &f.sha256, &f.sha512];
        text.extend(scan.detections.iter().map(|d| d.name.as_str()));
        let mut w = self.writer.lock().unwrap();
        w.delete_term(Term::from_field_text(self.id, &scan.id));
        w.add_document(doc!(self.id => scan.id.as_str(), self.text => text.join(" ")))?;
        w.commit()?;
        self.reader.reload()?;
        Ok(())
    }

    /// Scan ids matching `q`, best match first. Malformed queries are parsed leniently.
    pub fn search(&self, q: &str, limit: usize) -> Result<Vec<String>> {
        let parser = QueryParser::for_index(&self.index, vec![self.text]);
        let (parsed, _) = parser.parse_query_lenient(q);
        // The last word also matches as a prefix, so results appear while the user is still typing.
        // Tokens are split on non-alphanumerics like the index tokenizer, so they need no regex escaping.
        let last = q.split(|c: char| !c.is_alphanumeric()).rfind(|t| !t.is_empty()).map(str::to_lowercase);
        let query: Box<dyn Query> = match last {
            Some(t) => Box::new(BooleanQuery::new(vec![
                (Occur::Should, parsed),
                (Occur::Should, Box::new(RegexQuery::from_pattern(&format!("{t}.*"), self.text)?)),
            ])),
            None => parsed,
        };
        let searcher = self.reader.searcher();
        let hits = searcher.search(&query, &TopDocs::with_limit(limit).order_by_score())?;
        hits.into_iter()
            .map(|(_, addr)| {
                let d: TantivyDocument = searcher.doc(addr)?;
                Ok(d.get_first(self.id).and_then(|v| v.as_str()).unwrap_or_default().to_string())
            })
            .collect()
    }
}

fn schema() -> Schema {
    let mut b = Schema::builder();
    b.add_text_field("id", STRING | STORED);
    b.add_text_field("text", TEXT);
    b.build()
}
